#![forbid(unsafe_code)]

mod cli;
mod gui;

fn main() -> anyhow::Result<()> {
    if std::env::args_os().len() == 1 {
        gui::run()
    } else {
        cli::run()
    }
}
