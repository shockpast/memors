#[macro_export]
macro_rules! pcstr {
    ($str:expr) => {
        windows::core::PCSTR(format!("{}\0", $str).as_ptr())
    };
}
#[macro_export]
macro_rules! pcwstr {
    ($str:expr) => {
        windows::core::PCWSTR(format!("{}\0", $str).as_ptr())
    };
}