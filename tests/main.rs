use memors::{pattern::*, hook::*};

#[test]
fn code_to_struct() {
  assert_eq!(code("\\x00\\xFF\\x00"), Signature { bytes: vec![0, 255, 0], mask: vec![false, true, false] });
}

#[test]
fn ida_to_struct() {
  assert_eq!(ida("? FF ?"), Signature { bytes: vec![0, 255, 0], mask: vec![false, true, false] });
  assert_eq!(ida("?? FF ??"), Signature { bytes: vec![0, 255, 0], mask: vec![false, true, false] });
}