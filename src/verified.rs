//! Single source: Cargo erases contracts; Verus checks this exact executable code.
//! No assume(), external_body, or admit() is used in these contracts.
use vstd::prelude::*;
verus! {
pub fn debit(remaining:u64,cost:u64)->(out:Option<u64>)
 ensures
  cost <= remaining ==> out == Some((remaining-cost) as u64),
  cost > remaining ==> out.is_none(),
  out.is_some() ==> out.unwrap() <= remaining,
{
 if cost>remaining {None} else {Some(remaining-cost)}
}
pub fn add_coord(a:i64,b:i64)->(out:Option<i64>)
 ensures
  out.is_some() ==> -60000000 <= out.unwrap() <= 60000000,
  out.is_some() ==> out.unwrap() as int == a as int + b as int,
  -60000000 <= a <= 60000000 && -60000000 <= b <= 60000000
    && -60000000 <= a as int + b as int <= 60000000 ==> out.is_some(),
{
 if a < -60000000 || a > 60000000 || b < -60000000 || b > 60000000 {return None;}
 let n=a+b;
 if n < -60000000 || n > 60000000 {None} else {Some(n)}
}
pub fn contained(offset:u64,len:u64,capacity:u64)->(out:bool)
 ensures out == (offset as int + len as int <= capacity as int),
{
 offset <= capacity && len <= capacity-offset
}
pub fn rgba_length(width:u32,height:u32,stride:u32,limit:u64)->(out:Option<u64>)
 ensures
  out.is_some() ==> width>0 && height>0,
  out.is_some() ==> stride as int >= width as int * 4,
  out.is_some() ==> out.unwrap() as int == stride as int * height as int,
  out.is_some() ==> out.unwrap() <= limit,
  width>0 && height>0 && stride as int >= width as int*4
    && stride as int * height as int <= limit as int ==> out.is_some(),
{
 let row=(width as u64)*4;
 if width==0 || height==0 || (stride as u64)<row {return None;}
 assert((stride as int)*(height as int) <= 18446744065119617025int) by(nonlinear_arith)
  requires stride <= 4294967295, height <= 4294967295;
 let size=(stride as u64)*(height as u64);
 if size>limit {None} else {Some(size)}
}
pub fn premultiply_channel(channel:u8,alpha:u8)->(out:u8)
 ensures
  out as int == (channel as int * alpha as int + 127) / 255,
  out <= channel,
  out <= alpha,
  alpha == 0 ==> out == 0,
  alpha == 255 ==> out == channel,
{
 if alpha == 0 {return 0;}
 if alpha == 255 {return channel;}
 assert((channel as int)*(alpha as int) <= 65025int) by(nonlinear_arith)
  requires channel <= 255, alpha <= 255;
 let product=(channel as u32)*(alpha as u32);
 let result=(product+127)/255;
 assert(result <= channel as u32 && result <= alpha as u32) by(nonlinear_arith)
  requires channel <= 255, alpha <= 255,
   result == ((channel as int)*(alpha as int)+127)/255;
 result as u8
}
/// Extend occupancy in a bounded interval without changing any other column. A failed range
/// check leaves the vector unchanged. Used by the real table occupancy pass.
pub fn mark_columns(columns: &mut Vec<u64>, start: usize, span: usize, until: u64) -> (ok: bool)
 ensures
  final(columns).len() == old(columns).len(),
  ok == (start as int + span as int <= old(columns).len() as int),
  !ok ==> *final(columns) == *old(columns),
  ok ==> forall|i:int| 0 <= i < final(columns).len() ==>
   final(columns)[i] == if start <= i < start as int + span as int { if old(columns)[i] > until { old(columns)[i] } else { until } } else { old(columns)[i] },
{
 if start > columns.len() || span > columns.len() - start { return false; }
 let end = start + span;
 let mut i = start;
 while i < end
  invariant
   start <= i <= end <= columns.len(),
   end == start as int + span as int,
   columns.len() == old(columns).len(),
   forall|j:int| 0 <= j < columns.len() ==>
    columns[j] == if start <= j < i { if old(columns)[j] > until { old(columns)[j] } else { until } } else { old(columns)[j] },
  decreases end - i,
 {
  let value = if columns[i] > until { columns[i] } else { until };
  columns.set(i, value);
  i += 1;
 }
 true
}

}
