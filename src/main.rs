#![allow(clippy::let_and_return)]
pub mod gdrv3_ioctls;
pub mod util;

use windows::core::Result;
use gdrv3_ioctls::*;

fn main() -> Result<()>{
    let gb_driver = GigabyteDriver::new()?;
    println!("Opened a handle to the gigabyte device");

    /* Go nuts */

    Ok(())
}
