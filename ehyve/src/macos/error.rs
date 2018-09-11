use std::{result, fmt};
use hypervisor;

pub type Result<T> = result::Result<T, Error>;

#[derive(Debug,Clone)]
pub enum Error {
	FileMissing,
	InternalError,
	InvalidFile(String),
	NotEnoughMemory,
	MissingFrequency,
	Hypervisor(hypervisor::Error),
	UnknownExitReason(u32),
	UnknownIOPort(u16),
	Shutdown,
	ParseMemory,
	UnhandledExitReason
}

pub fn to_error(err: hypervisor::Error) -> Result<()>
{
	match err {
		hypervisor::Error::Success => Ok(()),
		_ => Err(Error::Hypervisor(err))
	}
}

impl fmt::Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match *self {
			Error::FileMissing => write!(f, "No execution file given"),
			Error::InternalError => write!(f, "An internal error has occurred, please report."),
			Error::InvalidFile(ref file) => write!(f, "The file {} was not found or is invalid.", file),
			Error::NotEnoughMemory => write!(f, "The host system has not enough memory, please check your memory usage."),
			Error::MissingFrequency => write!(f, "Couldn't get the CPU frequency from your system. (is /proc/cpuinfo missing?)"),
			Error::Hypervisor(ref err) => write!(f, "The hypervisor has failed: {:?}", err),
			Error::UnknownExitReason(ref exit_reason) => write!(f, "Unknown exit reason {:?}.", exit_reason),
			Error::UnknownIOPort(ref port) => write!(f, "Unknown io port 0x{}.", port),
			Error::Shutdown => write!(f, "Receives shutdown command"),
			Error::ParseMemory => write!(f, "Couldn't parse the guest memory size from the environment"),
			Error::UnhandledExitReason => write!(f, "Unhandled exit reason")
		}
	}
}