#[macro_export]
macro_rules! pack_unpack_inverse_test {
    ($($name:ident, $thing:expr)*) => {
    $(
        #[test]
        fn $name() {
            let mut thing = $thing;
            let i = thing.pack();
            println!("i (packed): {:x?}", i);
            let _ = thing.unpack(&mut i.clone()).expect("unpacking thing failed");
            let j = thing.pack();
            println!("j (unpked): {:x?}", j);
            assert_eq!(i, j);
        }
    )*
    }
}
