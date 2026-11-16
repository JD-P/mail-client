use crate::{
    Attachment, BackendError, FindingPresentation, FindingSeverity, FindingTargetKind,
    HeuristicCompilation, Message, Result,
};
use rustpython_parser::{ast, Parse};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value as JsonValue};
use std::collections::{BTreeSet, HashMap, HashSet};

const MAX_COMPILED_STEPS: u32 = 100_000;
const MAX_RUNTIME_STEPS: u32 = 100_000;
const MAX_ATTACHMENTS: u32 = 512;
const MAX_LINKS: u32 = 2_048;
const MAX_FINDINGS: usize = 2_048;
const MAX_EVIDENCE_FIELDS: usize = 32;
const MAX_STATIC_TEXT_BYTES: usize = 2_048;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct CompiledHeuristic {
    body: Vec<Statement>,
    pub required_features: Vec<String>,
    pub maximum_steps: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum Statement {
    Let {
        name: String,
        value: Expression,
    },
    If {
        condition: Expression,
        then_body: Vec<Statement>,
        else_body: Vec<Statement>,
    },
    ForAttachments {
        binding: String,
        body: Vec<Statement>,
    },
    ForLinks {
        binding: String,
        body: Vec<Statement>,
    },
    Yield(FindingTemplate),
    Return,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum Expression {
    Null,
    Bool(bool),
    Integer(i64),
    String(String),
    Path(Vec<String>),
    And(Vec<Expression>),
    Or(Vec<Expression>),
    Not(Box<Expression>),
    Negate(Box<Expression>),
    Arithmetic {
        left: Box<Expression>,
        operation: Arithmetic,
        right: Box<Expression>,
    },
    Compare {
        left: Box<Expression>,
        operations: Vec<Comparison>,
        comparators: Vec<Expression>,
    },
    Contains {
        value: Box<Expression>,
        needle: Box<Expression>,
        case_sensitive: bool,
    },
    StartsWith {
        value: Box<Expression>,
        prefix: Box<Expression>,
        case_sensitive: bool,
    },
    EndsWith {
        value: Box<Expression>,
        suffix: Box<Expression>,
        case_sensitive: bool,
    },
    Lower(Box<Expression>),
    IsMissing(Box<Expression>),
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
enum Comparison {
    Equal,
    NotEqual,
    Less,
    LessOrEqual,
    Greater,
    GreaterOrEqual,
    Is,
    IsNot,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
enum Arithmetic {
    Add,
    Subtract,
    Multiply,
    FloorDivide,
    Remainder,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct FindingTemplate {
    code: String,
    presentation: FindingPresentation,
    severity: FindingSeverity,
    target_kind: FindingTargetKind,
    target: Option<Expression>,
    text: Option<String>,
    evidence: Vec<(String, Expression)>,
}

#[derive(Clone, Debug)]
pub(crate) struct ProducedFinding {
    pub code: String,
    pub presentation: FindingPresentation,
    pub severity: FindingSeverity,
    pub target_kind: FindingTargetKind,
    pub target_id: Option<String>,
    pub text: Option<String>,
    pub evidence: JsonValue,
}

#[derive(Debug)]
pub(crate) enum HeuristicRunError {
    Budget,
    Failed(String),
}

/// Parse and authority-check Python-shaped Lizard Rules source without
/// executing a Python runtime. The report is suitable for previews before
/// activation. Value-type errors are isolated as failed evaluations.
pub fn compile_heuristic(source: &str) -> Result<HeuristicCompilation> {
    let program = compile_program(source)?;
    Ok(HeuristicCompilation {
        required_features: program.required_features,
        maximum_steps: program.maximum_steps,
    })
}

pub(crate) fn compile_program(source: &str) -> Result<CompiledHeuristic> {
    if source.len() > 64 * 1024 {
        return Err(compile_error("heuristic source exceeds 64 KiB"));
    }
    let suite = ast::Suite::parse(source, "<lizard-rule>")
        .map_err(|error| compile_error(format!("Python syntax error: {error}")))?;
    if suite.len() != 1 {
        return Err(compile_error(
            "a heuristic must contain exactly one decorated function",
        ));
    }
    let ast::Stmt::FunctionDef(function) = &suite[0] else {
        return Err(compile_error(
            "a heuristic must contain exactly one decorated function",
        ));
    };
    validate_function(function)?;

    let mut compiler = Compiler::default();
    let body = compiler.compile_block(&function.body, 0)?;
    let maximum_steps = statement_cost(&body)?;
    if maximum_steps > MAX_COMPILED_STEPS {
        return Err(compile_error(format!(
            "heuristic worst-case cost {maximum_steps} exceeds {MAX_COMPILED_STEPS} steps"
        )));
    }
    if !contains_yield(&body) {
        return Err(compile_error("heuristic never yields a Finding"));
    }
    Ok(CompiledHeuristic {
        body,
        required_features: compiler.required_features.into_iter().collect(),
        maximum_steps,
    })
}

pub(crate) fn run_program(
    program: &CompiledHeuristic,
    message: &Message,
) -> std::result::Result<Vec<ProducedFinding>, HeuristicRunError> {
    let mut runtime = Runtime {
        message,
        locals: HashMap::new(),
        steps: 0,
        findings: Vec::new(),
    };
    let _ = runtime.execute_block(&program.body)?;
    Ok(runtime.findings)
}

#[derive(Default)]
struct Compiler {
    locals: HashSet<String>,
    bindings: HashMap<String, BindingKind>,
    required_features: BTreeSet<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BindingKind {
    Attachment,
    Link,
}

impl Compiler {
    fn compile_block(&mut self, statements: &[ast::Stmt], depth: usize) -> Result<Vec<Statement>> {
        let mut compiled = Vec::with_capacity(statements.len());
        for statement in statements {
            compiled.push(match statement {
                ast::Stmt::Assign(assign) => {
                    if depth != 0 {
                        return Err(compile_error(
                            "local bindings are allowed only at the top of the function",
                        ));
                    }
                    if assign.targets.len() != 1 {
                        return Err(compile_error("tuple and chained assignment are forbidden"));
                    }
                    let ast::Expr::Name(target) = &assign.targets[0] else {
                        return Err(compile_error("only immutable local-name bindings are allowed"));
                    };
                    let name = target.id.to_string();
                    if name == "message" || self.locals.contains(&name) {
                        return Err(compile_error(format!(
                            "local {name:?} is reserved or assigned more than once"
                        )));
                    }
                    let value = self.compile_expression(&assign.value)?;
                    self.locals.insert(name.clone());
                    Statement::Let { name, value }
                }
                ast::Stmt::If(branch) => Statement::If {
                    condition: self.compile_expression(&branch.test)?,
                    then_body: self.compile_block(&branch.body, depth + 1)?,
                    else_body: self.compile_block(&branch.orelse, depth + 1)?,
                },
                ast::Stmt::For(loop_) => {
                    if !loop_.orelse.is_empty() {
                        return Err(compile_error("for/else is not supported"));
                    }
                    let ast::Expr::Name(target) = loop_.target.as_ref() else {
                        return Err(compile_error("for-loop targets must be a single name"));
                    };
                    let binding = target.id.to_string();
                    if binding == "message"
                        || self.locals.contains(&binding)
                        || self.bindings.contains_key(&binding)
                    {
                        return Err(compile_error(format!(
                            "loop binding {binding:?} shadows another name"
                        )));
                    }
                    let (binding_kind, feature) = if path_equals(
                        &loop_.iter,
                        &["message", "attachments"],
                    ) {
                        (BindingKind::Attachment, "attachments")
                    } else if path_equals(&loop_.iter, &["message", "links"]) {
                        (BindingKind::Link, "links")
                    } else {
                        return Err(compile_error(
                            "bounded for loops support only `message.attachments` and `message.links`",
                        ));
                    };
                    self.required_features.insert(feature.into());
                    self.bindings.insert(binding.clone(), binding_kind);
                    let body = self.compile_block(&loop_.body, depth + 1)?;
                    self.bindings.remove(&binding);
                    if binding_kind == BindingKind::Attachment {
                        Statement::ForAttachments { binding, body }
                    } else {
                        Statement::ForLinks { binding, body }
                    }
                }
                ast::Stmt::Return(return_) => {
                    if return_.value.is_some() {
                        return Err(compile_error("heuristics may only use bare `return`"));
                    }
                    Statement::Return
                }
                ast::Stmt::Expr(expression) => {
                    let ast::Expr::Yield(yield_) = expression.value.as_ref() else {
                        return Err(compile_error(
                            "standalone expressions are forbidden; use `yield Finding(...)`",
                        ));
                    };
                    let value = yield_
                        .value
                        .as_deref()
                        .ok_or_else(|| compile_error("a yielded Finding is required"))?;
                    Statement::Yield(self.compile_finding(value)?)
                }
                _ => {
                    return Err(compile_error(
                        "unsupported statement; imports, mutation, exceptions, while loops, async code, and nested definitions are forbidden",
                    ))
                }
            });
        }
        Ok(compiled)
    }

    fn compile_expression(&mut self, expression: &ast::Expr) -> Result<Expression> {
        match expression {
            ast::Expr::Constant(constant) => match &constant.value {
                ast::Constant::None => Ok(Expression::Null),
                ast::Constant::Bool(value) => Ok(Expression::Bool(*value)),
                ast::Constant::Str(value) => Ok(Expression::String(value.clone())),
                ast::Constant::Int(value) => value
                    .to_string()
                    .parse::<i64>()
                    .map(Expression::Integer)
                    .map_err(|_| {
                        compile_error("integer literal is outside the signed 64-bit range")
                    }),
                _ => Err(compile_error(
                    "only None, bool, string, and integer literals are supported",
                )),
            },
            ast::Expr::Name(name) => {
                let name = name.id.to_string();
                if self.locals.contains(&name) {
                    Ok(Expression::Path(vec![name]))
                } else {
                    Err(compile_error(format!("unknown name {name:?}")))
                }
            }
            ast::Expr::Attribute(_) => {
                let path = expression_path(expression)
                    .ok_or_else(|| compile_error("dynamic attribute access is forbidden"))?;
                self.validate_path(&path)?;
                Ok(Expression::Path(path))
            }
            ast::Expr::BoolOp(boolean) => {
                let values = boolean
                    .values
                    .iter()
                    .map(|value| self.compile_expression(value))
                    .collect::<Result<Vec<_>>>()?;
                match boolean.op {
                    ast::BoolOp::And => Ok(Expression::And(values)),
                    ast::BoolOp::Or => Ok(Expression::Or(values)),
                }
            }
            ast::Expr::UnaryOp(unary) if unary.op == ast::UnaryOp::Not => Ok(Expression::Not(
                Box::new(self.compile_expression(&unary.operand)?),
            )),
            ast::Expr::UnaryOp(unary) if unary.op == ast::UnaryOp::USub => Ok(Expression::Negate(
                Box::new(self.compile_expression(&unary.operand)?),
            )),
            ast::Expr::BinOp(binary) => {
                let operation = match binary.op {
                    ast::Operator::Add => Arithmetic::Add,
                    ast::Operator::Sub => Arithmetic::Subtract,
                    ast::Operator::Mult => Arithmetic::Multiply,
                    ast::Operator::FloorDiv => Arithmetic::FloorDivide,
                    ast::Operator::Mod => Arithmetic::Remainder,
                    _ => {
                        return Err(compile_error(
                            "only checked integer +, -, *, //, and % arithmetic is supported",
                        ))
                    }
                };
                Ok(Expression::Arithmetic {
                    left: Box::new(self.compile_expression(&binary.left)?),
                    operation,
                    right: Box::new(self.compile_expression(&binary.right)?),
                })
            }
            ast::Expr::Compare(compare) => {
                let operations = compare
                    .ops
                    .iter()
                    .map(|operation| match operation {
                        ast::CmpOp::Eq => Ok(Comparison::Equal),
                        ast::CmpOp::NotEq => Ok(Comparison::NotEqual),
                        ast::CmpOp::Lt => Ok(Comparison::Less),
                        ast::CmpOp::LtE => Ok(Comparison::LessOrEqual),
                        ast::CmpOp::Gt => Ok(Comparison::Greater),
                        ast::CmpOp::GtE => Ok(Comparison::GreaterOrEqual),
                        ast::CmpOp::Is => Ok(Comparison::Is),
                        ast::CmpOp::IsNot => Ok(Comparison::IsNot),
                        _ => Err(compile_error("`in` and `not in` are not supported")),
                    })
                    .collect::<Result<Vec<_>>>()?;
                Ok(Expression::Compare {
                    left: Box::new(self.compile_expression(&compare.left)?),
                    operations,
                    comparators: compare
                        .comparators
                        .iter()
                        .map(|value| self.compile_expression(value))
                        .collect::<Result<Vec<_>>>()?,
                })
            }
            ast::Expr::Call(call) => self.compile_call(call),
            _ => Err(compile_error(
                "unsupported expression; dynamic Python semantics are forbidden",
            )),
        }
    }

    fn compile_call(&mut self, call: &ast::ExprCall) -> Result<Expression> {
        if !call.keywords.is_empty() || call.args.len() > 1 {
            return Err(compile_error(
                "this pure method accepts exactly one positional argument",
            ));
        }
        let ast::Expr::Attribute(method) = call.func.as_ref() else {
            return Err(compile_error("only approved pure methods may be called"));
        };
        let name = method.attr.as_str();
        if matches!(name, "lower" | "is_missing") {
            if !call.args.is_empty() {
                return Err(compile_error(format!("{name}() accepts no arguments")));
            }
            let value = Box::new(self.compile_expression(&method.value)?);
            return Ok(if name == "lower" {
                Expression::Lower(value)
            } else {
                Expression::IsMissing(value)
            });
        }
        if call.args.len() != 1 {
            return Err(compile_error(format!("{name}() requires one argument")));
        }
        let value = Box::new(self.compile_expression(&method.value)?);
        let argument = Box::new(self.compile_expression(&call.args[0])?);
        match name {
            "contains" => Ok(Expression::Contains {
                value,
                needle: argument,
                case_sensitive: false,
            }),
            "contains_exact_case" => Ok(Expression::Contains {
                value,
                needle: argument,
                case_sensitive: true,
            }),
            "starts_with" => Ok(Expression::StartsWith {
                value,
                prefix: argument,
                case_sensitive: false,
            }),
            "ends_with" => Ok(Expression::EndsWith {
                value,
                suffix: argument,
                case_sensitive: false,
            }),
            _ => Err(compile_error(format!("method {name:?} is not permitted"))),
        }
    }

    fn validate_path(&mut self, path: &[String]) -> Result<()> {
        let string_path = path.iter().map(String::as_str).collect::<Vec<_>>();
        let feature = match string_path.as_slice() {
            ["message", "subject"]
            | ["message", "sender", "address"]
            | ["message", "sender", "domain"]
            | ["message", "sender", "registrable_domain"]
            | ["message", "sender", "claimed_name"]
            | ["message", "size_bytes"]
            | ["message", "has_attachment"] => "headers",
            ["message", "authentication", "dkim", "status"]
            | ["message", "authentication", "dkim", "has_aligned_pass"] => "authentication",
            ["message", "body_text"] => "body_text",
            [binding, "id" | "ordinal" | "name" | "declared_type" | "size" | "inline"]
                if self.bindings.get(*binding) == Some(&BindingKind::Attachment) =>
            {
                "attachments"
            }
            [binding, "id" | "ordinal" | "destination" | "scheme" | "host" | "registrable_domain"]
                if self.bindings.get(*binding) == Some(&BindingKind::Link) =>
            {
                "links"
            }
            [local] if self.locals.contains(*local) => return Ok(()),
            _ => {
                return Err(compile_error(format!(
                    "unknown or unavailable field `{}`",
                    path.join(".")
                )))
            }
        };
        self.required_features.insert(feature.into());
        Ok(())
    }

    fn compile_finding(&mut self, expression: &ast::Expr) -> Result<FindingTemplate> {
        let ast::Expr::Call(call) = expression else {
            return Err(compile_error("heuristics may yield only Finding(...)"));
        };
        if !path_equals(&call.func, &["Finding"]) || !call.args.is_empty() {
            return Err(compile_error(
                "heuristics may yield only keyword-based Finding(...)",
            ));
        }
        let mut keywords = HashMap::new();
        for keyword in &call.keywords {
            let name = keyword
                .arg
                .as_ref()
                .ok_or_else(|| compile_error("Finding does not accept **kwargs"))?
                .to_string();
            if keywords.insert(name.clone(), &keyword.value).is_some() {
                return Err(compile_error(format!(
                    "duplicate Finding argument {name:?}"
                )));
            }
        }
        let code = static_string(take_keyword(&mut keywords, "code")?, "code")?;
        if code.is_empty()
            || code.len() > 128
            || !code.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_.-".contains(&byte)
            })
        {
            return Err(compile_error(
                "Finding code must be 1-128 lowercase ASCII letters, digits, `_`, `-`, or `.`",
            ));
        }
        let presentation = parse_presentation(take_keyword(&mut keywords, "presentation")?)?;
        let severity = parse_severity(take_keyword(&mut keywords, "severity")?)?;
        let text = keywords
            .remove("text")
            .map(|value| static_string(value, "text"))
            .transpose()?;
        if text
            .as_ref()
            .is_some_and(|value| value.len() > MAX_STATIC_TEXT_BYTES)
        {
            return Err(compile_error("Finding text exceeds 2048 bytes"));
        }
        let target_source = keywords.remove("target");
        let target_kind = match presentation {
            FindingPresentation::LinkInterstitial => FindingTargetKind::Link,
            FindingPresentation::AttachmentInterstitial => FindingTargetKind::Attachment,
            _ => FindingTargetKind::Message,
        };
        if target_kind != FindingTargetKind::Message && target_source.is_none() {
            return Err(compile_error(
                "link and attachment interstitial findings require a target",
            ));
        }
        if target_kind == FindingTargetKind::Message && target_source.is_some() {
            return Err(compile_error(
                "message-level findings must not specify a target",
            ));
        }
        if let Some(target_source) = target_source {
            let expected = match target_kind {
                FindingTargetKind::Attachment => BindingKind::Attachment,
                FindingTargetKind::Link => BindingKind::Link,
                FindingTargetKind::Message => unreachable!(),
            };
            let path = expression_path(target_source).ok_or_else(|| {
                compile_error("finding target must be the bound object's `.id` field")
            })?;
            if path.len() != 2 || path[1] != "id" || self.bindings.get(&path[0]) != Some(&expected)
            {
                return Err(compile_error(
                    "finding target must be the matching attachment or link `.id` field",
                ));
            }
        }
        let target = target_source
            .map(|value| self.compile_expression(value))
            .transpose()?;
        let evidence = match keywords.remove("evidence") {
            None => Vec::new(),
            Some(ast::Expr::Dict(dictionary)) => {
                if dictionary.keys.len() > MAX_EVIDENCE_FIELDS {
                    return Err(compile_error("Finding evidence has more than 32 fields"));
                }
                dictionary
                    .keys
                    .iter()
                    .zip(&dictionary.values)
                    .map(|(key, value)| {
                        let key = key
                            .as_ref()
                            .ok_or_else(|| compile_error("Finding evidence forbids ** mappings"))?;
                        Ok((
                            static_string(key, "evidence key")?,
                            self.compile_expression(value)?,
                        ))
                    })
                    .collect::<Result<Vec<_>>>()?
            }
            Some(_) => {
                return Err(compile_error(
                    "Finding evidence must be a dictionary literal",
                ))
            }
        };
        if let Some(unknown) = keywords.keys().next() {
            return Err(compile_error(format!(
                "unknown Finding argument {unknown:?}"
            )));
        }
        Ok(FindingTemplate {
            code,
            presentation,
            severity,
            target_kind,
            target,
            text,
            evidence,
        })
    }
}

struct Runtime<'a> {
    message: &'a Message,
    locals: HashMap<String, RuntimeValue>,
    steps: u32,
    findings: Vec<ProducedFinding>,
}

#[derive(Clone, Debug)]
enum RuntimeValue {
    Null,
    Bool(bool),
    Integer(i64),
    String(String),
    Attachment(Attachment),
    Link(crate::MessageLink),
}

enum Flow {
    Continue,
    Return,
}

impl Runtime<'_> {
    fn step(&mut self) -> std::result::Result<(), HeuristicRunError> {
        self.steps = self.steps.saturating_add(1);
        if self.steps > MAX_RUNTIME_STEPS {
            Err(HeuristicRunError::Budget)
        } else {
            Ok(())
        }
    }

    fn execute_block(
        &mut self,
        statements: &[Statement],
    ) -> std::result::Result<Flow, HeuristicRunError> {
        for statement in statements {
            self.step()?;
            match statement {
                Statement::Let { name, value } => {
                    let value = self.evaluate(value)?;
                    self.locals.insert(name.clone(), value);
                }
                Statement::If {
                    condition,
                    then_body,
                    else_body,
                } => {
                    let matches = self.evaluate(condition)?.truthy();
                    let body = if matches { then_body } else { else_body };
                    if matches!(self.execute_block(body)?, Flow::Return) {
                        return Ok(Flow::Return);
                    }
                }
                Statement::ForAttachments { binding, body } => {
                    let attachments = self.message.attachments.clone();
                    for attachment in attachments.into_iter().take(MAX_ATTACHMENTS as usize) {
                        self.step()?;
                        self.locals
                            .insert(binding.clone(), RuntimeValue::Attachment(attachment));
                        if matches!(self.execute_block(body)?, Flow::Return) {
                            self.locals.remove(binding);
                            return Ok(Flow::Return);
                        }
                    }
                    self.locals.remove(binding);
                }
                Statement::ForLinks { binding, body } => {
                    let links = self.message.links.clone();
                    for link in links.into_iter().take(MAX_LINKS as usize) {
                        self.step()?;
                        self.locals
                            .insert(binding.clone(), RuntimeValue::Link(link));
                        if matches!(self.execute_block(body)?, Flow::Return) {
                            self.locals.remove(binding);
                            return Ok(Flow::Return);
                        }
                    }
                    self.locals.remove(binding);
                }
                Statement::Yield(template) => {
                    if self.findings.len() >= MAX_FINDINGS {
                        return Err(HeuristicRunError::Budget);
                    }
                    let finding = self.materialize(template)?;
                    self.findings.push(finding);
                }
                Statement::Return => return Ok(Flow::Return),
            }
        }
        Ok(Flow::Continue)
    }

    fn materialize(
        &mut self,
        template: &FindingTemplate,
    ) -> std::result::Result<ProducedFinding, HeuristicRunError> {
        let target_id = template
            .target
            .as_ref()
            .map(|target| self.evaluate(target).map(RuntimeValue::display))
            .transpose()?;
        let mut evidence = Map::new();
        for (key, value) in &template.evidence {
            evidence.insert(key.clone(), self.evaluate(value)?.json());
        }
        Ok(ProducedFinding {
            code: template.code.clone(),
            presentation: template.presentation,
            severity: template.severity,
            target_kind: template.target_kind,
            target_id,
            text: template.text.clone(),
            evidence: JsonValue::Object(evidence),
        })
    }

    fn evaluate(
        &mut self,
        expression: &Expression,
    ) -> std::result::Result<RuntimeValue, HeuristicRunError> {
        self.step()?;
        match expression {
            Expression::Null => Ok(RuntimeValue::Null),
            Expression::Bool(value) => Ok(RuntimeValue::Bool(*value)),
            Expression::Integer(value) => Ok(RuntimeValue::Integer(*value)),
            Expression::String(value) => Ok(RuntimeValue::String(value.clone())),
            Expression::Path(path) => self.resolve_path(path),
            Expression::And(values) => {
                for value in values {
                    if !self.evaluate(value)?.truthy() {
                        return Ok(RuntimeValue::Bool(false));
                    }
                }
                Ok(RuntimeValue::Bool(true))
            }
            Expression::Or(values) => {
                for value in values {
                    if self.evaluate(value)?.truthy() {
                        return Ok(RuntimeValue::Bool(true));
                    }
                }
                Ok(RuntimeValue::Bool(false))
            }
            Expression::Not(value) => Ok(RuntimeValue::Bool(!self.evaluate(value)?.truthy())),
            Expression::Negate(value) => {
                let value = self.evaluate(value)?.integer()?;
                value
                    .checked_neg()
                    .map(RuntimeValue::Integer)
                    .ok_or_else(|| runtime_error("integer negation overflow"))
            }
            Expression::Arithmetic {
                left,
                operation,
                right,
            } => {
                let left = self.evaluate(left)?.integer()?;
                let right = self.evaluate(right)?.integer()?;
                let value = match operation {
                    Arithmetic::Add => left.checked_add(right),
                    Arithmetic::Subtract => left.checked_sub(right),
                    Arithmetic::Multiply => left.checked_mul(right),
                    Arithmetic::FloorDivide => python_floor_div(left, right),
                    Arithmetic::Remainder => python_remainder(left, right),
                }
                .ok_or_else(|| runtime_error("invalid or overflowing integer arithmetic"))?;
                Ok(RuntimeValue::Integer(value))
            }
            Expression::Compare {
                left,
                operations,
                comparators,
            } => {
                let mut left = self.evaluate(left)?;
                for (operation, comparator) in operations.iter().zip(comparators) {
                    let right = self.evaluate(comparator)?;
                    if !compare_values(&left, *operation, &right)? {
                        return Ok(RuntimeValue::Bool(false));
                    }
                    left = right;
                }
                Ok(RuntimeValue::Bool(true))
            }
            Expression::Contains {
                value,
                needle,
                case_sensitive,
            } => {
                let value = self.evaluate(value)?.string()?;
                let needle = self.evaluate(needle)?.string()?;
                self.charge_text(value.len().saturating_add(needle.len()))?;
                Ok(RuntimeValue::Bool(if *case_sensitive {
                    value.contains(&needle)
                } else {
                    value.to_lowercase().contains(&needle.to_lowercase())
                }))
            }
            Expression::StartsWith {
                value,
                prefix,
                case_sensitive,
            } => {
                let value = self.evaluate(value)?.string()?;
                let prefix = self.evaluate(prefix)?.string()?;
                self.charge_text(value.len().saturating_add(prefix.len()))?;
                Ok(RuntimeValue::Bool(if *case_sensitive {
                    value.starts_with(&prefix)
                } else {
                    value.to_lowercase().starts_with(&prefix.to_lowercase())
                }))
            }
            Expression::EndsWith {
                value,
                suffix,
                case_sensitive,
            } => {
                let value = self.evaluate(value)?.string()?;
                let suffix = self.evaluate(suffix)?.string()?;
                self.charge_text(value.len().saturating_add(suffix.len()))?;
                Ok(RuntimeValue::Bool(if *case_sensitive {
                    value.ends_with(&suffix)
                } else {
                    value.to_lowercase().ends_with(&suffix.to_lowercase())
                }))
            }
            Expression::Lower(value) => {
                let value = self.evaluate(value)?.string()?;
                self.charge_text(value.len())?;
                Ok(RuntimeValue::String(value.to_lowercase()))
            }
            Expression::IsMissing(value) => Ok(RuntimeValue::Bool(matches!(
                self.evaluate(value)?,
                RuntimeValue::Null
            ))),
        }
    }

    /// String work is charged in addition to AST nodes so a short program
    /// cannot repeatedly scan a multi-megabyte message under a nominally tiny
    /// step count.
    fn charge_text(&mut self, bytes: usize) -> std::result::Result<(), HeuristicRunError> {
        let chunks = bytes.saturating_add(63) / 64;
        let chunks = u32::try_from(chunks).unwrap_or(u32::MAX);
        self.steps = self.steps.saturating_add(chunks);
        if self.steps > MAX_RUNTIME_STEPS {
            Err(HeuristicRunError::Budget)
        } else {
            Ok(())
        }
    }

    fn resolve_path(
        &self,
        path: &[String],
    ) -> std::result::Result<RuntimeValue, HeuristicRunError> {
        let names = path.iter().map(String::as_str).collect::<Vec<_>>();
        let value = match names.as_slice() {
            ["message", "subject"] => option_string(self.message.summary.subject.clone()),
            ["message", "sender", "address"] => {
                option_string(self.message.summary.from_address.clone())
            }
            ["message", "sender", "domain"] => option_string(
                self.message
                    .summary
                    .from_address
                    .as_deref()
                    .and_then(|address| {
                        address
                            .rsplit_once('@')
                            .map(|(_, domain)| domain.to_owned())
                    }),
            ),
            ["message", "sender", "registrable_domain"] => option_string(
                self.message
                    .summary
                    .from_address
                    .as_deref()
                    .and_then(|address| address.rsplit_once('@').map(|(_, domain)| domain))
                    .and_then(psl::domain_str)
                    .map(str::to_owned),
            ),
            ["message", "sender", "claimed_name"] => {
                option_string(self.message.summary.from_name.clone())
            }
            ["message", "body_text"] => RuntimeValue::String(self.message.body_text.clone()),
            ["message", "size_bytes"] => RuntimeValue::Integer(
                i64::try_from(self.message.summary.size_bytes).unwrap_or(i64::MAX),
            ),
            ["message", "has_attachment"] => {
                RuntimeValue::Bool(self.message.summary.has_attachment)
            }
            ["message", "authentication", "dkim", "status"] => RuntimeValue::String(
                match self.message.dkim.status {
                    crate::DkimAuthenticationStatus::Unsigned => "unsigned",
                    crate::DkimAuthenticationStatus::Pass => "pass",
                    crate::DkimAuthenticationStatus::Failed => "failed",
                    crate::DkimAuthenticationStatus::TemporaryFailure => "temporary_failure",
                    crate::DkimAuthenticationStatus::NotEvaluated => "not_evaluated",
                }
                .into(),
            ),
            ["message", "authentication", "dkim", "has_aligned_pass"] => {
                RuntimeValue::Bool(self.message.dkim.signatures.iter().any(|signature| {
                    signature.status == crate::DkimSignatureStatus::Pass
                        && signature.from_domain_aligned == Some(true)
                }))
            }
            [local] => self
                .locals
                .get(*local)
                .cloned()
                .ok_or_else(|| runtime_error(format!("local {local:?} has no value")))?,
            [binding, field] => {
                match self
                    .locals
                    .get(*binding)
                    .ok_or_else(|| runtime_error(format!("binding {binding:?} has no value")))?
                {
                    RuntimeValue::Attachment(attachment) => match *field {
                        "id" => RuntimeValue::String(attachment.id.clone()),
                        "ordinal" => RuntimeValue::Integer(i64::from(attachment.ordinal)),
                        "name" => option_string(attachment.name.clone()),
                        "declared_type" => option_string(attachment.declared_media_type.clone()),
                        "size" => RuntimeValue::Integer(
                            i64::try_from(attachment.decoded_size).unwrap_or(i64::MAX),
                        ),
                        "inline" => RuntimeValue::Bool(attachment.inline),
                        _ => {
                            return Err(runtime_error(format!(
                                "unknown attachment field {field:?}"
                            )))
                        }
                    },
                    RuntimeValue::Link(link) => match *field {
                        "id" => RuntimeValue::String(link.id.clone()),
                        "ordinal" => RuntimeValue::Integer(i64::from(link.ordinal)),
                        "destination" => RuntimeValue::String(link.destination.clone()),
                        "scheme" => RuntimeValue::String(link.scheme.clone()),
                        "host" => option_string(link.host.clone()),
                        "registrable_domain" => option_string(link.registrable_domain.clone()),
                        _ => return Err(runtime_error(format!("unknown link field {field:?}"))),
                    },
                    _ => {
                        return Err(runtime_error(format!(
                            "{binding:?} is not a collection item"
                        )))
                    }
                }
            }
            _ => return Err(runtime_error(format!("unknown field `{}`", path.join(".")))),
        };
        Ok(value)
    }
}

fn python_floor_div(left: i64, right: i64) -> Option<i64> {
    let quotient = left.checked_div(right)?;
    let remainder = left.checked_rem(right)?;
    if remainder != 0 && (left < 0) != (right < 0) {
        quotient.checked_sub(1)
    } else {
        Some(quotient)
    }
}

fn python_remainder(left: i64, right: i64) -> Option<i64> {
    let remainder = left.checked_rem(right)?;
    if remainder != 0 && (left < 0) != (right < 0) {
        remainder.checked_add(right)
    } else {
        Some(remainder)
    }
}

impl RuntimeValue {
    fn truthy(&self) -> bool {
        match self {
            Self::Null => false,
            Self::Bool(value) => *value,
            Self::Integer(value) => *value != 0,
            Self::String(value) => !value.is_empty(),
            Self::Attachment(_) => true,
            Self::Link(_) => true,
        }
    }

    fn string(self) -> std::result::Result<String, HeuristicRunError> {
        match self {
            Self::String(value) => Ok(value),
            Self::Null => Ok(String::new()),
            _ => Err(runtime_error(
                "string operation received a non-string value",
            )),
        }
    }

    fn integer(self) -> std::result::Result<i64, HeuristicRunError> {
        match self {
            Self::Integer(value) => Ok(value),
            _ => Err(runtime_error("arithmetic received a non-integer value")),
        }
    }

    fn display(self) -> String {
        match self {
            Self::Null => "null".into(),
            Self::Bool(value) => value.to_string(),
            Self::Integer(value) => value.to_string(),
            Self::String(value) => value,
            Self::Attachment(value) => value.ordinal.to_string(),
            Self::Link(value) => value.id,
        }
    }

    fn json(self) -> JsonValue {
        match self {
            Self::Null => JsonValue::Null,
            Self::Bool(value) => JsonValue::Bool(value),
            Self::Integer(value) => value.into(),
            Self::String(value) => value.into(),
            Self::Attachment(value) => value.ordinal.into(),
            Self::Link(value) => value.id.into(),
        }
    }
}

fn validate_function(function: &ast::StmtFunctionDef) -> Result<()> {
    if function.name.as_str() != "detect" {
        return Err(compile_error("heuristic function must be named `detect`"));
    }
    if function.decorator_list.len() != 1
        || !path_equals(&function.decorator_list[0], &["heuristic"])
    {
        return Err(compile_error("heuristic function requires `@heuristic`"));
    }
    let arguments = &function.args;
    if !arguments.posonlyargs.is_empty()
        || arguments.args.len() != 1
        || arguments.args[0].def.arg.as_str() != "message"
        || arguments.args[0].default.is_some()
        || arguments.vararg.is_some()
        || !arguments.kwonlyargs.is_empty()
        || arguments.kwarg.is_some()
    {
        return Err(compile_error(
            "detect must have exactly one argument: `def detect(message):`",
        ));
    }
    if function.returns.is_some() || !function.type_params.is_empty() {
        return Err(compile_error(
            "annotations and generic parameters are not supported",
        ));
    }
    Ok(())
}

fn expression_path(expression: &ast::Expr) -> Option<Vec<String>> {
    match expression {
        ast::Expr::Name(name) => Some(vec![name.id.to_string()]),
        ast::Expr::Attribute(attribute) => {
            let mut path = expression_path(&attribute.value)?;
            path.push(attribute.attr.to_string());
            Some(path)
        }
        _ => None,
    }
}

fn path_equals(expression: &ast::Expr, expected: &[&str]) -> bool {
    expression_path(expression)
        .is_some_and(|path| path.iter().map(String::as_str).eq(expected.iter().copied()))
}

fn take_keyword<'a>(
    values: &mut HashMap<String, &'a ast::Expr>,
    name: &str,
) -> Result<&'a ast::Expr> {
    values
        .remove(name)
        .ok_or_else(|| compile_error(format!("Finding requires {name}=")))
}

fn static_string(expression: &ast::Expr, name: &str) -> Result<String> {
    if let ast::Expr::Constant(constant) = expression {
        if let ast::Constant::Str(value) = &constant.value {
            return Ok(value.clone());
        }
    }
    Err(compile_error(format!(
        "Finding {name} must be a static string"
    )))
}

fn static_name_or_string(expression: &ast::Expr, name: &str) -> Result<String> {
    if let Some(path) = expression_path(expression) {
        if path.len() == 1 {
            return Ok(path[0].clone());
        }
    }
    static_string(expression, name)
}

fn parse_presentation(expression: &ast::Expr) -> Result<FindingPresentation> {
    match static_name_or_string(expression, "presentation")?.as_str() {
        "MessageAnnotation" | "message_annotation" => Ok(FindingPresentation::MessageAnnotation),
        "PersistentWarningFooter" | "persistent_warning_footer" => {
            Ok(FindingPresentation::PersistentWarningFooter)
        }
        "OpenInterstitial" | "open_interstitial" => Ok(FindingPresentation::OpenInterstitial),
        "LinkInterstitial" | "link_interstitial" => Ok(FindingPresentation::LinkInterstitial),
        "AttachmentInterstitial" | "attachment_interstitial" => {
            Ok(FindingPresentation::AttachmentInterstitial)
        }
        value => Err(compile_error(format!("unknown presentation {value:?}"))),
    }
}

fn parse_severity(expression: &ast::Expr) -> Result<FindingSeverity> {
    match static_name_or_string(expression, "severity")?.as_str() {
        "Information" | "information" => Ok(FindingSeverity::Information),
        "Warning" | "warning" => Ok(FindingSeverity::Warning),
        "Danger" | "danger" => Ok(FindingSeverity::Danger),
        value => Err(compile_error(format!("unknown severity {value:?}"))),
    }
}

fn statement_cost(statements: &[Statement]) -> Result<u32> {
    let mut total = 0_u32;
    for statement in statements {
        let cost = match statement {
            Statement::Let { value, .. } => 1_u32.saturating_add(expression_cost(value)),
            Statement::If {
                condition,
                then_body,
                else_body,
            } => 1_u32
                .saturating_add(expression_cost(condition))
                .saturating_add(statement_cost(then_body)?.max(statement_cost(else_body)?)),
            Statement::ForAttachments { body, .. } => 1_u32.saturating_add(
                MAX_ATTACHMENTS.saturating_mul(1_u32.saturating_add(statement_cost(body)?)),
            ),
            Statement::ForLinks { body, .. } => 1_u32.saturating_add(
                MAX_LINKS.saturating_mul(1_u32.saturating_add(statement_cost(body)?)),
            ),
            Statement::Yield(template) => {
                1_u32.saturating_add(template.evidence.iter().fold(0_u32, |cost, (_, value)| {
                    cost.saturating_add(expression_cost(value))
                }))
            }
            Statement::Return => 1,
        };
        total = total.saturating_add(cost);
    }
    Ok(total)
}

fn expression_cost(expression: &Expression) -> u32 {
    match expression {
        Expression::And(values) | Expression::Or(values) => {
            values.iter().fold(1_u32, |cost, value| {
                cost.saturating_add(expression_cost(value))
            })
        }
        Expression::Not(value)
        | Expression::Negate(value)
        | Expression::Lower(value)
        | Expression::IsMissing(value) => 1_u32.saturating_add(expression_cost(value)),
        Expression::Arithmetic { left, right, .. } => 1_u32
            .saturating_add(expression_cost(left))
            .saturating_add(expression_cost(right)),
        Expression::Compare {
            left, comparators, ..
        } => comparators.iter().fold(
            1_u32.saturating_add(expression_cost(left)),
            |cost, value| cost.saturating_add(expression_cost(value)),
        ),
        Expression::Contains { value, needle, .. } => 1_u32
            .saturating_add(expression_cost(value))
            .saturating_add(expression_cost(needle)),
        Expression::StartsWith { value, prefix, .. } => 1_u32
            .saturating_add(expression_cost(value))
            .saturating_add(expression_cost(prefix)),
        Expression::EndsWith { value, suffix, .. } => 1_u32
            .saturating_add(expression_cost(value))
            .saturating_add(expression_cost(suffix)),
        _ => 1,
    }
}

fn contains_yield(statements: &[Statement]) -> bool {
    statements.iter().any(|statement| match statement {
        Statement::Yield(_) => true,
        Statement::If {
            then_body,
            else_body,
            ..
        } => contains_yield(then_body) || contains_yield(else_body),
        Statement::ForAttachments { body, .. } => contains_yield(body),
        Statement::ForLinks { body, .. } => contains_yield(body),
        _ => false,
    })
}

fn compare_values(
    left: &RuntimeValue,
    operation: Comparison,
    right: &RuntimeValue,
) -> std::result::Result<bool, HeuristicRunError> {
    let result = match operation {
        Comparison::Equal | Comparison::Is => equal_values(left, right),
        Comparison::NotEqual | Comparison::IsNot => !equal_values(left, right),
        Comparison::Less => ordered_values(left, right, |ordering| ordering.is_lt())?,
        Comparison::LessOrEqual => ordered_values(left, right, |ordering| ordering.is_le())?,
        Comparison::Greater => ordered_values(left, right, |ordering| ordering.is_gt())?,
        Comparison::GreaterOrEqual => ordered_values(left, right, |ordering| ordering.is_ge())?,
    };
    Ok(result)
}

fn equal_values(left: &RuntimeValue, right: &RuntimeValue) -> bool {
    match (left, right) {
        (RuntimeValue::Null, RuntimeValue::Null) => true,
        (RuntimeValue::Bool(left), RuntimeValue::Bool(right)) => left == right,
        (RuntimeValue::Integer(left), RuntimeValue::Integer(right)) => left == right,
        (RuntimeValue::String(left), RuntimeValue::String(right)) => left == right,
        _ => false,
    }
}

fn ordered_values(
    left: &RuntimeValue,
    right: &RuntimeValue,
    predicate: impl FnOnce(std::cmp::Ordering) -> bool,
) -> std::result::Result<bool, HeuristicRunError> {
    let ordering = match (left, right) {
        (RuntimeValue::Integer(left), RuntimeValue::Integer(right)) => left.cmp(right),
        (RuntimeValue::String(left), RuntimeValue::String(right)) => left.cmp(right),
        _ => {
            return Err(runtime_error(
                "ordered comparison requires matching numbers or strings",
            ))
        }
    };
    Ok(predicate(ordering))
}

fn option_string(value: Option<String>) -> RuntimeValue {
    value.map_or(RuntimeValue::Null, RuntimeValue::String)
}

fn compile_error(message: impl Into<String>) -> BackendError {
    BackendError::InvalidInput(format!("heuristic compile error: {}", message.into()))
}

fn runtime_error(message: impl Into<String>) -> HeuristicRunError {
    HeuristicRunError::Failed(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_python_with_side_effect_authority() {
        for source in [
            "import os\n@heuristic\ndef detect(message):\n    yield Finding(code='x', presentation=MessageAnnotation, severity=Warning)\n",
            "@heuristic\ndef detect(message):\n    while True:\n        pass\n",
            "@heuristic\ndef detect(message):\n    message.subject = 'changed'\n",
        ] {
            assert!(compile_program(source).is_err(), "source should fail: {source}");
        }
    }

    #[test]
    fn compiles_bounded_attachment_detector() {
        let source = r#"
@heuristic
def detect(message):
    if message.sender.domain != "example.com":
        return
    for attachment in message.attachments:
        if attachment.declared_type == "application/x-executable":
            yield Finding(
                code="executable_attachment",
                presentation=AttachmentInterstitial,
                severity=Danger,
                target=attachment.id,
                evidence={"declared_type": attachment.declared_type},
            )
"#;
        let compiled = compile_program(source).unwrap();
        assert_eq!(compiled.required_features, vec!["attachments", "headers"]);
        assert!(compiled.maximum_steps <= MAX_COMPILED_STEPS);
    }

    #[test]
    fn integer_division_matches_python_floor_semantics() {
        assert_eq!(python_floor_div(-3, 2), Some(-2));
        assert_eq!(python_remainder(-3, 2), Some(1));
        assert_eq!(python_floor_div(3, -2), Some(-2));
        assert_eq!(python_remainder(3, -2), Some(-1));
        assert_eq!(python_floor_div(i64::MIN, -1), None);
        assert_eq!(python_remainder(1, 0), None);
    }
}
