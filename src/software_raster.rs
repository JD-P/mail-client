//! Bounded software coverage rasterization for Gecko's snapshot paint path.
//!
//! Firefox screenshots recorded with `WindowGlobal.drawSnapshot` use Skia's
//! analytic, quarter-pixel path rasterizer rather than the WebRender border
//! shader used on screen.  Keep the small rounded-path subset we need here so
//! conformance does not require shipping a second native graphics stack.
//!
//! The analytic edge stepping is adapted from Skia's anti-aliased path
//! rasterizer. See `LICENSE-SKIA.txt` and `THIRD-PARTY.md`.

const ONE: i64 = 1 << 16;
const HALF: i64 = ONE >> 1;
const MAX_FIXED: i64 = i32::MAX as i64;

#[derive(Clone, Copy)]
struct Point {
    x: f32,
    y: f32,
}

#[derive(Clone)]
struct Cubic {
    cx: i64,
    cy: i64,
    cdx: i64,
    cdy: i64,
    cddx: i64,
    cddy: i64,
    cdddx: i64,
    cdddy: i64,
    last_x: i64,
    last_y: i64,
    snapped_y: i64,
    shift: u32,
    d_shift: u32,
    count: i32,
}

#[derive(Clone)]
struct Edge {
    x: i64,
    dx: i64,
    upper_x: i64,
    y: i64,
    upper_y: i64,
    lower_y: i64,
    dy: i64,
    winding: i8,
    cubic: Option<Cubic>,
    finished: bool,
}

fn snap_y(value: i64) -> i64 {
    ((value + (ONE >> 3)) >> 14) << 14
}

fn fixed_mul(a: i64, b: i64) -> i64 {
    (a * b) >> 16
}

fn fdot6_div(a: i64, b: i64) -> i64 {
    (a << 16) / b
}

fn quick_inverse(value: i64) -> i64 {
    debug_assert_ne!(value, 0);
    4_194_304 / value
}

fn quick_div(a: i64, b: i64) -> i64 {
    if (8..1024).contains(&b.abs()) && a.abs() < 4096 {
        (a * quick_inverse(b)) >> 6
    } else {
        fdot6_div(a, b)
    }
}

fn reciprocal_slope(slope: i64, dx: i64, dy: i64) -> i64 {
    if dx == 0 || slope == 0 {
        return MAX_FIXED;
    }
    let compact = (slope >> 10).abs();
    if compact == 0 {
        return MAX_FIXED;
    }
    if compact < 1024 {
        quick_inverse(compact)
    } else {
        quick_div(dy >> 10, dx >> 10).abs()
    }
}

impl Edge {
    fn update_line(
        &mut self,
        mut x0: i64,
        mut y0: i64,
        mut x1: i64,
        mut y1: i64,
        slope: i64,
    ) -> bool {
        if y0 > y1 {
            std::mem::swap(&mut x0, &mut x1);
            std::mem::swap(&mut y0, &mut y1);
            self.winding = -self.winding;
        }
        let dx = (x1 - x0) >> 10;
        let dy = (y1 - y0) >> 10;
        if dy == 0 {
            return false;
        }
        self.x = x0;
        self.dx = slope;
        self.upper_x = x0;
        self.y = y0;
        self.upper_y = y0;
        self.lower_y = y1;
        self.dy = reciprocal_slope(slope, dx, dy);
        true
    }

    fn line(a: Point, b: Point, orientation: i8) -> Option<Self> {
        let to_quarter_fdot6 = |value: f32| (f64::from(value) * 256.0).round_ties_even() as i64;
        let mut x0 = to_quarter_fdot6(a.x) << 8;
        let mut y0 = snap_y(to_quarter_fdot6(a.y) << 8);
        let mut x1 = to_quarter_fdot6(b.x) << 8;
        let mut y1 = snap_y(to_quarter_fdot6(b.y) << 8);
        let mut winding = orientation;
        if y0 > y1 {
            std::mem::swap(&mut x0, &mut x1);
            std::mem::swap(&mut y0, &mut y1);
            winding = -winding;
        }
        let dy = (y1 - y0) >> 10;
        if dy == 0 {
            return None;
        }
        let dx = (x1 - x0) >> 10;
        let slope = fdot6_div(dx, dy);
        Some(Self {
            x: x0,
            dx: slope,
            upper_x: x0,
            y: y0,
            upper_y: y0,
            lower_y: y1,
            dy: reciprocal_slope(slope, dx, dy),
            winding,
            cubic: None,
            finished: false,
        })
    }

    fn cubic(mut points: [Point; 4], orientation: i8) -> Option<Self> {
        let to_quarter_fdot6 = |value: f32| (f64::from(value) * 256.0).round_ties_even() as i64;
        let mut values = points.map(|point| (to_quarter_fdot6(point.x), to_quarter_fdot6(point.y)));
        let mut winding = orientation;
        if values[0].1 > values[3].1 {
            points.reverse();
            values.reverse();
            winding = -winding;
        }
        let [(x0, y0), (x1, y1), (x2, y2), (x3, y3)] = values;
        if ((y0 + 32) >> 6) == ((y3 + 32) >> 6) {
            return None;
        }
        let delta = |a: i64, b: i64, c: i64, d: i64| {
            let one_third = (a * 8 - b * 15 + c * 6 + d) * 19 >> 9;
            let two_thirds = (a + b * 6 - c * 15 + d * 8) * 19 >> 9;
            one_third.abs().max(two_thirds.abs())
        };
        let cheap_distance = |a: i64, b: i64| {
            let (a, b) = (a.abs(), b.abs());
            if a > b {
                a + (b >> 1)
            } else {
                b + (a >> 1)
            }
        };
        let distance = (cheap_distance(delta(x0, x1, x2, x3), delta(y0, y1, y2, y3)) + 16) >> 5;
        let mut shift = (64 - distance.leading_zeros() as u32) >> 1;
        shift += 1;
        shift = shift.min(6);
        let mut up_shift = 6u32;
        let mut down_shift = shift as i32 + up_shift as i32 - 10;
        if down_shift < 0 {
            down_shift = 0;
            up_shift = 10 - shift;
        }
        let coefficients = |a: i64, b: i64, c: i64, d: i64| {
            let bb = (3 * (b - a)) << up_shift;
            let cc = (3 * (a - b - b + c)) << up_shift;
            let dd = (d + 3 * (b - c) - a) << up_shift;
            (
                (a << 10) >> 2,
                (bb + (cc >> shift) + (dd >> (2 * shift))) >> 2,
                (2 * cc + ((3 * dd) >> (shift - 1))) >> 2,
                ((3 * dd) >> (shift - 1)) >> 2,
                (d << 10) >> 2,
            )
        };
        let (cx, cdx, cddx, cdddx, last_x) = coefficients(x0, x1, x2, x3);
        let (mut cy, cdy, cddy, cdddy, mut last_y) = coefficients(y0, y1, y2, y3);
        cy = snap_y(cy);
        last_y = snap_y(last_y);
        let cubic = Cubic {
            cx,
            cy,
            cdx,
            cdy,
            cddx,
            cddy,
            cdddx,
            cdddy,
            last_x,
            last_y,
            snapped_y: cy,
            shift,
            d_shift: down_shift as u32,
            count: -(1i32 << shift),
        };
        let mut edge = Self {
            x: cx,
            dx: 0,
            upper_x: cx,
            y: cy,
            upper_y: cy,
            lower_y: cy,
            dy: MAX_FIXED,
            winding,
            cubic: Some(cubic),
            finished: false,
        };
        edge.update_cubic().then_some(edge)
    }

    fn keep_continuous(&mut self) {
        if let Some(cubic) = &mut self.cubic {
            cubic.cx = self.x;
            cubic.snapped_y = self.y;
        }
    }

    fn update_cubic(&mut self) -> bool {
        let Some(mut cubic) = self.cubic.take() else {
            return false;
        };
        let mut count = cubic.count;
        let mut old_x = cubic.cx;
        let mut old_y = cubic.cy;
        let (new_x, new_y, success) = loop {
            count += 1;
            let (new_x, mut new_y) = if count < 0 {
                let x = old_x + (cubic.cdx >> cubic.d_shift);
                cubic.cdx += cubic.cddx >> cubic.shift;
                cubic.cddx += cubic.cdddx;
                let y = old_y + (cubic.cdy >> cubic.d_shift);
                cubic.cdy += cubic.cddy >> cubic.shift;
                cubic.cddy += cubic.cdddy;
                (x, y)
            } else {
                (cubic.last_x, cubic.last_y)
            };
            new_y = new_y.max(old_y);
            let mut snapped = snap_y(new_y);
            if cubic.last_y < snapped {
                snapped = cubic.last_y;
                count = 0;
            }
            let dy = (snapped - cubic.snapped_y) >> 10;
            let slope = if dy == 0 {
                MAX_FIXED
            } else {
                fdot6_div((new_x - old_x) >> 10, dy)
            };
            let success = slope < MAX_FIXED
                && self.update_line(old_x, cubic.snapped_y, new_x, snapped, slope);
            old_x = new_x;
            old_y = new_y;
            cubic.snapped_y = snapped;
            if success || count >= 0 {
                break (new_x, new_y, success);
            }
        };
        cubic.cx = new_x;
        cubic.cy = new_y;
        cubic.count = count;
        self.cubic = Some(cubic);
        success
    }

    fn advance_curve(&mut self, target_y: i64) -> bool {
        let mut updates = 0;
        while self.lower_y <= target_y {
            updates += 1;
            if updates >= 128 {
                self.finished = true;
                return false;
            }
            if self.cubic.is_none() {
                self.finished = true;
                return false;
            }
            self.keep_continuous();
            if !self.update_cubic() {
                self.finished = true;
                return false;
            }
        }
        true
    }

    fn go_y(&mut self, target: i64) {
        if target == self.y + ONE {
            self.x += self.dx;
            self.y = target;
        } else if target != self.y {
            self.x = self.upper_x + fixed_mul(self.dx, target - self.upper_y);
            self.y = target;
        }
    }

    fn go_y_step(&mut self, target: i64, shift: u32) {
        self.y = target;
        self.x += self.dx >> shift;
    }

    fn smooth_cubic(&self) -> bool {
        let Some(cubic) = &self.cubic else {
            return self.lower_y - self.upper_y >= ONE;
        };
        (cubic.cdx.abs() >> 1) >= (cubic.cddx.abs() >> cubic.shift)
            && (cubic.cdy.abs() >> 1) >= (cubic.cddy.abs() >> cubic.shift)
            && ((cubic.cdy - (cubic.cddy >> cubic.shift)) >> cubic.d_shift) >= ONE
    }
}

fn floor(value: i64) -> i32 {
    (value >> 16) as i32
}

fn ceil(value: i64) -> i32 {
    ((value + ONE - 1) >> 16) as i32
}

fn partial_alpha(alpha: u8, height: i64) -> u8 {
    (((i64::from(alpha) * height + HALF) >> 16).clamp(0, 255)) as u8
}

fn scale_alpha(alpha: u8, full: u8) -> u8 {
    if full == 255 {
        alpha
    } else {
        ((u16::from(alpha) * u16::from(full)) >> 8) as u8
    }
}

fn scale_single_alpha(alpha: u8, full: u8, direct_blit: bool) -> u8 {
    if full == 255 && direct_blit {
        alpha
    } else {
        ((u16::from(alpha) * u16::from(full)) >> 8) as u8
    }
}

fn trapezoid_alpha(a: i64, b: i64) -> u8 {
    (((a + b) / 2) >> 8).clamp(0, 255) as u8
}

fn triangle_alpha(a: i64, b: i64) -> u8 {
    let area = (a >> 11) * (a >> 11) * (b >> 11);
    ((area >> 8) & 0xff) as u8
}

fn add(mask: &mut [u8], width: usize, row: i32, x: i32, value: u8) {
    if row < 0 || x < 0 {
        return;
    }
    let Some(index) = (row as usize)
        .checked_mul(width)
        .and_then(|offset| offset.checked_add(x as usize))
        .filter(|index| *index < mask.len())
    else {
        return;
    };
    mask[index] = mask[index].saturating_add(value);
}

fn mark_fast(fast: &mut [bool], width: usize, row: i32, x: i32) {
    if row < 0 || x < 0 {
        return;
    }
    if let Some(value) = (row as usize)
        .checked_mul(width)
        .and_then(|offset| offset.checked_add(x as usize))
        .and_then(|index| fast.get_mut(index))
    {
        *value = true;
    }
}

fn snap_rle_alphas(mask: &mut [u8], direct: &[bool]) {
    for (index, alpha) in mask.iter_mut().enumerate() {
        if direct.get(index).copied().unwrap_or(false) {
            continue;
        }
        *alpha = if *alpha > 247 {
            255
        } else if *alpha < 8 {
            0
        } else {
            *alpha
        };
    }
}

fn compute_above(left: i64, right: i64, dy: i64, full: u8) -> Vec<u8> {
    let count = ceil(right).max(0) as usize;
    let mut output = vec![0; count];
    match count {
        0 => {}
        1 => {
            output[0] = scale_alpha(
                (((2 * ONE - left - right) >> 9) as i32).clamp(0, 255) as u8,
                full,
            )
        }
        _ => {
            let first = ONE - left;
            let last = right - ((count as i64 - 1) << 16);
            let first_height = fixed_mul(first, dy);
            output[0] = (fixed_mul(first, first_height) >> 9).clamp(0, 255) as u8;
            let mut alpha = first_height + (dy >> 1);
            for item in &mut output[1..count - 1] {
                *item = (alpha >> 8).clamp(0, 255) as u8;
                alpha += dy;
            }
            output[count - 1] = full.saturating_sub(triangle_alpha(last, dy));
        }
    }
    output
}

fn compute_below(left: i64, right: i64, dy: i64, full: u8) -> Vec<u8> {
    let count = ceil(right).max(0) as usize;
    let mut output = vec![0; count];
    match count {
        0 => {}
        1 => output[0] = scale_alpha(trapezoid_alpha(left, right), full),
        _ => {
            let first = ONE - left;
            let last = right - ((count as i64 - 1) << 16);
            let last_height = fixed_mul(last, dy);
            output[count - 1] = (fixed_mul(last, last_height) >> 9).clamp(0, 255) as u8;
            let mut alpha = last_height + (dy >> 1);
            for index in (1..count - 1).rev() {
                output[index] = ((alpha >> 8) & 0xff) as u8;
                alpha += dy;
            }
            output[0] = full.saturating_sub(triangle_alpha(first, dy));
        }
    }
    output
}

#[allow(clippy::too_many_arguments)]
fn raster_wide_trapezoid(
    mask: &mut [u8],
    direct: &mut [bool],
    vertical: &mut [bool],
    allow_vertical: bool,
    width: usize,
    row: i32,
    upper_left: i64,
    upper_right: i64,
    lower_left: i64,
    lower_right: i64,
    left_dy: i64,
    right_dy: i64,
    full: u8,
) {
    let left = floor(upper_left);
    let right = ceil(lower_right);
    let len = (right - left).max(0) as usize;
    if len == 0 {
        return;
    }
    if len == 1 {
        add(
            mask,
            width,
            row,
            left,
            scale_single_alpha(
                trapezoid_alpha(upper_right - upper_left, lower_right - lower_left),
                full,
                allow_vertical,
            ),
        );
        if full == 255 {
            mark_fast(direct, width, row, left);
            if allow_vertical {
                mark_fast(vertical, width, row, left);
            }
        }
        return;
    }
    let mut alphas = vec![full; len];
    let upper_left_pixel = floor(upper_left);
    let lower_left_pixel = ceil(lower_left);
    if upper_left_pixel + 2 == lower_left_pixel {
        let first = (i64::from(upper_left_pixel) << 16) + ONE - upper_left;
        let second = lower_left - upper_left - first;
        alphas[0] = alphas[0].saturating_sub(full.saturating_sub(triangle_alpha(first, left_dy)));
        alphas[1] = alphas[1].saturating_sub(triangle_alpha(second, left_dy));
    } else {
        let temporary = compute_below(
            upper_left - (i64::from(upper_left_pixel) << 16),
            lower_left - (i64::from(upper_left_pixel) << 16),
            left_dy,
            full,
        );
        for pixel in upper_left_pixel..lower_left_pixel {
            let output = (pixel - left) as usize;
            let input = (pixel - upper_left_pixel) as usize;
            alphas[output] = alphas[output].saturating_sub(temporary[input]);
        }
    }
    let upper_right_pixel = floor(upper_right);
    let lower_right_pixel = ceil(lower_right);
    if upper_right_pixel + 2 == lower_right_pixel {
        let first = (i64::from(upper_right_pixel) << 16) + ONE - upper_right;
        let second = lower_right - upper_right - first;
        let a = triangle_alpha(first, right_dy);
        let b = full.saturating_sub(triangle_alpha(second, right_dy));
        alphas[len - 2] = alphas[len - 2].saturating_sub(a);
        alphas[len - 1] = alphas[len - 1].saturating_sub(b);
    } else {
        let temporary = compute_above(
            upper_right - (i64::from(upper_right_pixel) << 16),
            lower_right - (i64::from(upper_right_pixel) << 16),
            right_dy,
            full,
        );
        for pixel in upper_right_pixel..lower_right_pixel {
            let output = (pixel - left) as usize;
            let input = (pixel - upper_right_pixel) as usize;
            alphas[output] = alphas[output].saturating_sub(temporary[input]);
        }
    }
    for (offset, alpha) in alphas.into_iter().enumerate() {
        add(mask, width, row, left + offset as i32, alpha);
        if full == 255 {
            mark_fast(direct, width, row, left + offset as i32);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn raster_trapezoid(
    mask: &mut [u8],
    fast: &mut [bool],
    direct: &mut [bool],
    vertical: &mut [bool],
    allow_vertical: bool,
    quantize_terminal_right: bool,
    width: usize,
    row: i32,
    mut upper_left: i64,
    mut upper_right: i64,
    mut lower_left: i64,
    mut lower_right: i64,
    left_dy: i64,
    right_dy: i64,
    full: u8,
) {
    if upper_left > upper_right {
        return;
    }
    if lower_left > lower_right {
        let intersection = (upper_left.max(lower_left) + upper_right.min(lower_right)) / 2;
        lower_left = intersection;
        lower_right = intersection;
    }
    if upper_left == upper_right && lower_left == lower_right {
        return;
    }
    if upper_left > lower_left {
        std::mem::swap(&mut upper_left, &mut lower_left);
    }
    if upper_right > lower_right {
        std::mem::swap(&mut upper_right, &mut lower_right);
    }
    let join_left = (lower_left + ONE - 1) & !(ONE - 1);
    let join_right = upper_right & !(ONE - 1);
    if join_left > join_right {
        raster_wide_trapezoid(
            mask,
            direct,
            vertical,
            allow_vertical,
            width,
            row,
            upper_left,
            upper_right,
            lower_left,
            lower_right,
            left_dy,
            right_dy,
            full,
        );
        return;
    }
    if upper_left < join_left {
        let len = ceil(join_left - upper_left);
        if len == 1 {
            let alpha = trapezoid_alpha(join_left - upper_left, join_left - lower_left);
            add(
                mask,
                width,
                row,
                floor(upper_left),
                scale_single_alpha(alpha, full, allow_vertical),
            );
            if full == 255 {
                mark_fast(direct, width, row, floor(upper_left));
                if allow_vertical {
                    mark_fast(vertical, width, row, floor(upper_left));
                }
            }
        } else if len == 2 {
            let first = join_left - ONE - upper_left;
            let second = lower_left - upper_left - first;
            add(
                mask,
                width,
                row,
                floor(upper_left),
                triangle_alpha(first, left_dy),
            );
            if full == 255 {
                mark_fast(fast, width, row, floor(upper_left));
                mark_fast(fast, width, row, floor(upper_left) + 1);
                mark_fast(direct, width, row, floor(upper_left));
                mark_fast(direct, width, row, floor(upper_left) + 1);
            }
            add(
                mask,
                width,
                row,
                floor(upper_left) + 1,
                full.saturating_sub(triangle_alpha(second, left_dy)),
            );
        } else {
            raster_wide_trapezoid(
                mask,
                direct,
                vertical,
                allow_vertical,
                width,
                row,
                upper_left,
                join_left,
                lower_left,
                join_left,
                left_dy,
                MAX_FIXED,
                full,
            );
        }
    }
    for x in floor(join_left)..floor(join_right) {
        add(mask, width, row, x, full);
        if full == 255 {
            mark_fast(direct, width, row, x);
        }
    }
    if lower_right > join_right {
        let len = ceil(lower_right - join_right);
        if len == 1 {
            let alpha = trapezoid_alpha(upper_right - join_right, lower_right - join_right);
            add(
                mask,
                width,
                row,
                floor(join_right),
                scale_single_alpha(
                    alpha,
                    full,
                    allow_vertical && !(quantize_terminal_right && alpha <= 31),
                ),
            );
            if full == 255 {
                mark_fast(direct, width, row, floor(join_right));
                if allow_vertical {
                    mark_fast(vertical, width, row, floor(join_right));
                }
            }
        } else if len == 2 {
            let first = join_right + ONE - upper_right;
            let second = lower_right - upper_right - first;
            add(
                mask,
                width,
                row,
                floor(join_right),
                full.saturating_sub(triangle_alpha(first, right_dy)),
            );
            if full == 255 {
                mark_fast(fast, width, row, floor(join_right));
                mark_fast(fast, width, row, floor(join_right) + 1);
                mark_fast(direct, width, row, floor(join_right));
                mark_fast(direct, width, row, floor(join_right) + 1);
            }
            add(
                mask,
                width,
                row,
                floor(join_right) + 1,
                triangle_alpha(second, right_dy),
            );
        } else {
            raster_wide_trapezoid(
                mask,
                direct,
                vertical,
                allow_vertical,
                width,
                row,
                join_right,
                upper_right,
                join_right,
                lower_right,
                MAX_FIXED,
                right_dy,
                full,
            );
        }
    }
}

fn rounded_edges(
    x: f32,
    y: f32,
    width: f32,
    height: f32,
    radius: f32,
    orientation: i8,
) -> Vec<Edge> {
    let radius = radius.min(width / 2.0).min(height / 2.0).max(0.0);
    let k = 0.551_914_97f32 * radius;
    let mut edges = Vec::with_capacity(6);
    let push_cubic = |edges: &mut Vec<Edge>, points| {
        if let Some(edge) = Edge::cubic(points, orientation) {
            edges.push(edge);
        }
    };
    push_cubic(
        &mut edges,
        [
            Point {
                x: x + width - radius,
                y,
            },
            Point {
                x: x + width - radius + k,
                y,
            },
            Point {
                x: x + width,
                y: y + radius - k,
            },
            Point {
                x: x + width,
                y: y + radius,
            },
        ],
    );
    if let Some(edge) = Edge::line(
        Point {
            x: x + width,
            y: y + radius,
        },
        Point {
            x: x + width,
            y: y + height - radius,
        },
        orientation,
    ) {
        edges.push(edge);
    }
    push_cubic(
        &mut edges,
        [
            Point {
                x: x + width,
                y: y + height - radius,
            },
            Point {
                x: x + width,
                y: y + height - radius + k,
            },
            Point {
                x: x + width - radius + k,
                y: y + height,
            },
            Point {
                x: x + width - radius,
                y: y + height,
            },
        ],
    );
    push_cubic(
        &mut edges,
        [
            Point {
                x: x + radius,
                y: y + height,
            },
            Point {
                x: x + radius - k,
                y: y + height,
            },
            Point {
                x,
                y: y + height - radius + k,
            },
            Point {
                x,
                y: y + height - radius,
            },
        ],
    );
    if let Some(edge) = Edge::line(
        Point {
            x,
            y: y + height - radius,
        },
        Point { x, y: y + radius },
        orientation,
    ) {
        edges.push(edge);
    }
    push_cubic(
        &mut edges,
        [
            Point { x, y: y + radius },
            Point {
                x,
                y: y + radius - k,
            },
            Point {
                x: x + radius - k,
                y,
            },
            Point { x: x + radius, y },
        ],
    );
    edges
}

fn polygon_edges(points: &[(f32, f32)]) -> Vec<Edge> {
    if points.len() < 3 {
        return Vec::new();
    }
    let mut edges = Vec::with_capacity(points.len());
    for index in 0..points.len() {
        let (x0, y0) = points[index];
        let (x1, y1) = points[(index + 1) % points.len()];
        if let Some(edge) = Edge::line(Point { x: x0, y: y0 }, Point { x: x1, y: y1 }, 1) {
            edges.push(edge);
        }
    }
    edges
}

fn circle_edges(center_x: f32, center_y: f32, radius: f32) -> Vec<Edge> {
    if radius <= 0.0 {
        return Vec::new();
    }
    let quarter_turn = std::f32::consts::FRAC_PI_2;
    let kappa = (4.0f32 / 3.0) * (quarter_turn / 4.0).tan();
    let mut edges = Vec::with_capacity(4);
    let mut angle = 0.0f32;
    let mut start = Point {
        x: center_x + radius,
        y: center_y,
    };
    for _ in 0..4 {
        let end_angle = angle + quarter_turn;
        let (start_sin, start_cos) = angle.sin_cos();
        let (end_sin, end_cos) = end_angle.sin_cos();
        let end = Point {
            x: center_x + end_cos * radius,
            y: center_y + end_sin * radius,
        };
        let control_1 = Point {
            x: start.x - start_sin * radius * kappa,
            y: start.y + start_cos * radius * kappa,
        };
        let control_2 = Point {
            x: end.x + end_sin * radius * kappa,
            y: end.y - end_cos * radius * kappa,
        };
        if let Some(edge) = Edge::cubic([start, control_1, control_2, end], 1) {
            edges.push(edge);
        }
        start = end;
        angle = end_angle;
    }
    edges
}

pub fn polygons_raster(
    width: u32,
    height: u32,
    polygons: &[Vec<(f32, f32)>],
) -> (Vec<u8>, Vec<bool>) {
    let edges = polygons
        .iter()
        .flat_map(|points| polygon_edges(points))
        .collect();
    let (mask, fast, _) = raster_edges(width, height, edges, false);
    (mask, fast)
}

pub fn circles_raster(
    width: u32,
    height: u32,
    circles: &[(f32, f32, f32)],
) -> (Vec<u8>, Vec<bool>) {
    let edges = circles
        .iter()
        .flat_map(|&(center_x, center_y, radius)| circle_edges(center_x, center_y, radius))
        .collect();
    let (mask, fast, _) = raster_edges(width, height, edges, false);
    (mask, fast)
}

fn raster_edges(
    width: u32,
    height: u32,
    mut edges: Vec<Edge>,
    force_rle: bool,
) -> (Vec<u8>, Vec<bool>, Vec<bool>) {
    let width_usize = width as usize;
    let mut mask = vec![0u8; width_usize * height as usize];
    let mut fast = vec![false; mask.len()];
    let mut direct = vec![false; mask.len()];
    let mut vertical = vec![false; mask.len()];
    let right_clip = i64::from(width) << 16;
    let Some(mut y) = edges.iter().map(|edge| edge.upper_y).min() else {
        return (mask, fast, vertical);
    };
    for edge in edges.iter_mut().filter(|edge| edge.upper_y <= y) {
        edge.go_y(y);
    }
    let stop = i64::from(height) << 16;
    let mut iterations = 0usize;
    while y < stop {
        iterations += 1;
        if iterations >= (height as usize).saturating_mul(64).saturating_add(1024) {
            break;
        }
        let mut active: Vec<usize> = edges
            .iter()
            .enumerate()
            .filter(|(_, edge)| !edge.finished && edge.upper_y <= y && edge.lower_y > y)
            .map(|(index, _)| index)
            .collect();
        if active.is_empty() {
            let Some(next) = edges
                .iter()
                .filter(|edge| !edge.finished && edge.upper_y > y)
                .map(|edge| edge.upper_y)
                .min()
            else {
                break;
            };
            y = next;
            for edge in edges
                .iter_mut()
                .filter(|edge| edge.upper_y <= y && edge.y < y)
            {
                edge.go_y(y);
            }
            continue;
        }
        active.sort_by_key(|index| (edges[*index].x, edges[*index].dx));
        let event = edges
            .iter()
            .filter(|edge| !edge.finished)
            .filter_map(|edge| {
                if edge.upper_y > y {
                    Some(edge.upper_y)
                } else if edge.lower_y > y {
                    Some(edge.lower_y)
                } else {
                    None
                }
            })
            .min()
            .unwrap_or(stop);
        let mut next_y = event.min((y + 1 + ONE - 1) & !(ONE - 1));
        let delta = next_y - y;
        let y_shift = if delta & (ONE >> 2) != 0 {
            next_y = y + (ONE >> 2);
            2
        } else if delta & (ONE >> 1) != 0 {
            next_y = y + (ONE >> 1);
            1
        } else {
            0
        };
        if next_y <= y {
            break;
        }
        let full = partial_alpha(255, next_y - y);
        let mut winding = 0i32;
        let mut inside = false;
        let mut left = 0i64;
        let mut next_left = 0i64;
        let mut left_dy = 0i64;
        let mut previous_right_pixel = floor(0);
        for (position, &index) in active.iter().enumerate() {
            let before = edges[index].x;
            winding += i32::from(edges[index].winding);
            let was_inside = inside;
            inside = winding != 0;
            let is_left = inside && !was_inside;
            let is_right = !inside && was_inside;
            edges[index].go_y_step(next_y, y_shift);
            let after = edges[index].x;
            if is_left {
                left = before.clamp(0, right_clip);
                next_left = after.clamp(0, right_clip);
                left_dy = edges[index].dy;
            } else if is_right {
                let previous_edge_close =
                    previous_right_pixel > floor(left) || previous_right_pixel > floor(next_left);
                let next_edge_close = active.get(position + 1).is_some_and(|next_index| {
                    let next = &edges[*next_index];
                    next.upper_y < next_y && after + ONE >= next.x - next.dx.abs()
                });
                let terminal_cubic = edges[index]
                    .cubic
                    .as_ref()
                    .is_some_and(|cubic| cubic.count == 0);
                raster_trapezoid(
                    &mut mask,
                    &mut fast,
                    &mut direct,
                    &mut vertical,
                    !force_rle && !previous_edge_close && !next_edge_close,
                    terminal_cubic,
                    width_usize,
                    floor(y),
                    left,
                    before.clamp(0, right_clip),
                    next_left,
                    after.clamp(0, right_clip),
                    left_dy,
                    edges[index].dy,
                    full,
                );
                previous_right_pixel = ceil(before.max(after));
            }
            edges[index].advance_curve(next_y);
        }
        y = next_y;
    }
    if width > 32 {
        snap_rle_alphas(&mut mask, &direct);
    }
    (mask, fast, vertical)
}

fn convex_corner_mask(radius: u32) -> Vec<u8> {
    if radius == 0 {
        return Vec::new();
    }
    let radius_f = radius as f32;
    let k = 0.551_914_97f32 * radius_f;
    let Some(mut left_edge) = Edge::cubic(
        [
            Point {
                x: radius_f,
                y: 0.0,
            },
            Point {
                x: radius_f - k,
                y: 0.0,
            },
            Point {
                x: 0.0,
                y: radius_f - k,
            },
            Point {
                x: 0.0,
                y: radius_f,
            },
        ],
        1,
    ) else {
        return vec![255; radius as usize * radius as usize];
    };
    let Some(mut right_edge) = Edge::cubic(
        [
            Point {
                x: radius_f,
                y: 0.0,
            },
            Point {
                x: radius_f + k,
                y: 0.0,
            },
            Point {
                x: radius_f * 2.0,
                y: radius_f - k,
            },
            Point {
                x: radius_f * 2.0,
                y: radius_f,
            },
        ],
        1,
    ) else {
        return vec![255; radius as usize * radius as usize];
    };
    let span_width = radius as usize * 2;
    let mut span = vec![0u8; span_width * radius as usize];
    let mut span_fast = vec![false; span.len()];
    let mut span_direct = vec![false; span.len()];
    let mut span_vertical = vec![false; span.len()];
    let mut y = left_edge.upper_y.max(right_edge.upper_y);
    let stop = i64::from(radius) << 16;
    let mut iterations = 0usize;
    while y < stop {
        iterations += 1;
        if iterations >= (radius as usize).saturating_mul(64).saturating_add(1024) {
            break;
        }
        while left_edge.lower_y <= y {
            if !left_edge.update_cubic() {
                return span
                    .chunks_exact(span_width)
                    .flat_map(|row| row[..radius as usize].iter().copied())
                    .collect();
            }
        }
        while right_edge.lower_y <= y {
            if !right_edge.update_cubic() {
                return span
                    .chunks_exact(span_width)
                    .flat_map(|row| row[..radius as usize].iter().copied())
                    .collect();
            }
        }
        left_edge.go_y(y);
        right_edge.go_y(y);
        if left_edge.x > right_edge.x
            || (left_edge.x == right_edge.x && left_edge.dx > right_edge.dx)
        {
            std::mem::swap(&mut left_edge, &mut right_edge);
        }
        let lower = left_edge.lower_y.min(right_edge.lower_y);
        let end = if left_edge.smooth_cubic() && right_edge.smooth_cubic() {
            (lower + ONE - 1) & !(ONE - 1)
        } else {
            lower
        }
        .min(stop);
        if end <= y {
            break;
        }
        let snap_half = ONE >> 5;
        let snap_mask = !((ONE >> 4) - 1);
        let mut left = left_edge.x.max(0) + snap_half;
        let mut right = right_edge.x.min(i64::from(radius * 2) << 16) + snap_half;
        let mut count = ceil(end) - floor(y);
        if count > 1 && y & (ONE - 1) != 0 {
            count -= 1;
            let next_y = (y + 1 + ONE - 1) & !(ONE - 1);
            let dy = next_y - y;
            let next_left = left + fixed_mul(left_edge.dx, dy);
            let next_right = right + fixed_mul(right_edge.dx, dy);
            raster_trapezoid(
                &mut span,
                &mut span_fast,
                &mut span_direct,
                &mut span_vertical,
                false,
                false,
                span_width,
                floor(y),
                left & snap_mask,
                right & snap_mask,
                next_left & snap_mask,
                next_right & snap_mask,
                left_edge.dy,
                right_edge.dy,
                partial_alpha(255, dy),
            );
            left = next_left;
            right = next_right;
            y = next_y;
        }
        while count > 1 {
            count -= 1;
            let next_left = left + left_edge.dx;
            let next_right = right + right_edge.dx;
            raster_trapezoid(
                &mut span,
                &mut span_fast,
                &mut span_direct,
                &mut span_vertical,
                false,
                false,
                span_width,
                floor(y),
                left & snap_mask,
                right & snap_mask,
                next_left & snap_mask,
                next_right & snap_mask,
                left_edge.dy,
                right_edge.dy,
                255,
            );
            left = next_left;
            right = next_right;
            y += ONE;
        }
        let dy = end - y;
        let next_left = (left + fixed_mul(left_edge.dx, dy)).max(snap_half);
        let next_right =
            (right + fixed_mul(right_edge.dx, dy)).min((i64::from(radius * 2) << 16) + snap_half);
        raster_trapezoid(
            &mut span,
            &mut span_fast,
            &mut span_direct,
            &mut span_vertical,
            false,
            false,
            span_width,
            floor(y),
            left & snap_mask,
            right & snap_mask,
            next_left & snap_mask,
            next_right & snap_mask,
            left_edge.dy,
            right_edge.dy,
            partial_alpha(255, dy),
        );
        left = next_left - snap_half;
        right = next_right - snap_half;
        y = end;
        left_edge.x = left;
        left_edge.y = y;
        right_edge.x = right;
        right_edge.y = y;
    }
    let mut corner = vec![0; radius as usize * radius as usize];
    for row in 0..radius as usize {
        corner[row * radius as usize..(row + 1) * radius as usize]
            .copy_from_slice(&span[row * span_width..row * span_width + radius as usize]);
    }
    corner
}

pub fn rounded_rect_mask(width: u32, height: u32, radius: f32) -> Vec<u8> {
    let radius = radius.round().clamp(0.0, (width.min(height) / 2) as f32) as u32;
    let mut mask = vec![255; width as usize * height as usize];
    if radius == 0 {
        return mask;
    }
    let corner = convex_corner_mask(radius);
    for y in 0..radius {
        for x in 0..radius {
            let alpha = corner[(y * radius + x) as usize];
            for (px, py) in [
                (x, y),
                (width - 1 - x, y),
                (x, height - 1 - y),
                (width - 1 - x, height - 1 - y),
            ] {
                mask[(py * width + px) as usize] = alpha;
            }
        }
    }
    if width > 32 {
        let direct = vec![false; mask.len()];
        snap_rle_alphas(&mut mask, &direct);
    }
    mask
}

pub fn rounded_border_raster(
    width: u32,
    height: u32,
    radius: f32,
    inset: f32,
) -> (Vec<u8>, Vec<bool>, Vec<bool>) {
    let mut edges = rounded_edges(0.0, 0.0, width as f32, height as f32, radius, 1);
    let inner_width = width as f32 - inset * 2.0;
    let inner_height = height as f32 - inset * 2.0;
    if inner_width > 0.0 && inner_height > 0.0 {
        edges.extend(rounded_edges(
            inset,
            inset,
            inner_width,
            inner_height,
            (radius - inset).max(0.0),
            -1,
        ));
    }
    raster_edges(width, height, edges, false)
}

pub fn rounded_border_mask(width: u32, height: u32, radius: f32, inset: f32) -> Vec<u8> {
    rounded_border_raster(width, height, radius, inset).0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gecko_quarter_pixel_rounded_edge() {
        let mask = rounded_rect_mask(40, 40, 20.0);
        assert_eq!(
            &mask[..20],
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 28, 96, 164, 228, 255, 255]
        );
    }

    #[test]
    fn rounded_inner_edge_remains_hollow() {
        let mask = rounded_border_mask(208, 108, 20.0, 4.0);
        assert_eq!(mask[54 * 208], 255);
        assert_eq!(mask[54 * 208 + 3], 255);
        assert_eq!(mask[54 * 208 + 4], 0);
        assert_eq!(mask[54 * 208 + 100], 0);
    }

    #[test]
    fn nearly_vertical_slopes_do_not_divide_by_zero() {
        assert_eq!(reciprocal_slope(1, 1, 1), MAX_FIXED);
    }
}
