use byteorder::{ReadBytesExt, WriteBytesExt, LE};

pub trait BoolExt<T, E, F: FnOnce() -> Result<T, E>> {
    fn then_try(&self, f: F) -> Result<Option<T>, E>;
}

impl<T, E, F: FnOnce() -> Result<T, E>> BoolExt<T, E, F> for bool {
    fn then_try(&self, f: F) -> Result<Option<T>, E> {
        self.then(f).transpose()
    }
}

pub trait ReadExt {
    fn read_bool(&mut self) -> Result<bool, super::Error>;
    fn read_guid(&mut self) -> Result<[u8; 20], super::Error>;
    fn read_array<T>(
        &mut self,
        func: impl FnMut(&mut Self) -> Result<T, super::Error>,
    ) -> Result<Vec<T>, super::Error>;
    fn read_array_len<T>(
        &mut self,
        len: usize,
        func: impl FnMut(&mut Self) -> Result<T, super::Error>,
    ) -> Result<Vec<T>, super::Error>;
    fn read_string(&mut self) -> Result<String, super::Error>;
    fn read_len(&mut self, len: usize) -> Result<Vec<u8>, super::Error>;
}

pub trait WriteExt {
    fn write_bool(&mut self, value: bool) -> Result<(), super::Error>;
    fn write_string(&mut self, value: &str) -> Result<(), super::Error>;
}

impl<R: std::io::Read> ReadExt for R {
    fn read_bool(&mut self) -> Result<bool, super::Error> {
        match self.read_u8()? {
            1 => Ok(true),
            0 => Ok(false),
            err => Err(super::Error::Bool(err)),
        }
    }

    fn read_guid(&mut self) -> Result<[u8; 20], super::Error> {
        let mut guid = [0; 20];
        self.read_exact(&mut guid)?;
        Ok(guid)
    }

    fn read_array<T>(
        &mut self,
        func: impl FnMut(&mut Self) -> Result<T, super::Error>,
    ) -> Result<Vec<T>, super::Error> {
        let len = self.read_u32::<LE>()? as usize;
        self.read_array_len(len, func)
    }

    fn read_array_len<T>(
        &mut self,
        len: usize,
        mut func: impl FnMut(&mut Self) -> Result<T, super::Error>,
    ) -> Result<Vec<T>, super::Error> {
        let mut buf = Vec::new();
        buf.try_reserve_exact(len).map_err(|_| {
            super::Error::Other(format!("array length {len} is too large to allocate"))
        })?;
        for _ in 0..len {
            buf.push(func(self)?);
        }
        Ok(buf)
    }

    fn read_string(&mut self) -> Result<String, super::Error> {
        let len = self.read_i32::<LE>()?;
        if len < 0 {
            let len = len
                .checked_neg()
                .ok_or_else(|| super::Error::Other("invalid UTF-16 FString length".to_owned()))?;
            let chars = self.read_array_len(len as usize, |r| Ok(r.read_u16::<LE>()?))?;
            let length = chars.iter().position(|&c| c == 0).unwrap_or(chars.len());
            Ok(String::from_utf16(&chars[..length])?)
        } else {
            let chars = self.read_len(len as usize)?;
            let length = chars.iter().position(|&c| c == 0).unwrap_or(chars.len());
            Ok(String::from_utf8_lossy(&chars[..length]).into_owned())
        }
    }

    fn read_len(&mut self, len: usize) -> Result<Vec<u8>, super::Error> {
        let mut buf = Vec::new();
        buf.try_reserve_exact(len).map_err(|_| {
            super::Error::Other(format!("byte length {len} is too large to allocate"))
        })?;
        buf.resize(len, 0);
        self.read_exact(&mut buf)?;
        Ok(buf)
    }
}

impl<W: std::io::Write> WriteExt for W {
    fn write_bool(&mut self, value: bool) -> Result<(), super::Error> {
        self.write_u8(match value {
            true => 1,
            false => 0,
        })?;
        Ok(())
    }
    fn write_string(&mut self, value: &str) -> Result<(), super::Error> {
        if value.is_empty() || value.is_ascii() {
            self.write_u32::<LE>(value.len() as u32 + 1)?;
            self.write_all(value.as_bytes())?;
            self.write_u8(0)?;
        } else {
            let chars: Vec<u16> = value.encode_utf16().collect();
            self.write_i32::<LE>(-(chars.len() as i32 + 1))?;
            for c in chars {
                self.write_u16::<LE>(c)?;
            }
            self.write_u16::<LE>(0)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::ReadExt;
    use byteorder::{WriteBytesExt, LE};
    use std::io::Cursor;

    #[test]
    fn invalid_utf16_fstring_returns_an_error() {
        let mut bytes = Vec::new();
        bytes.write_i32::<LE>(-2).unwrap();
        bytes.write_u16::<LE>(0xd800).unwrap();
        bytes.write_u16::<LE>(0).unwrap();

        let error = Cursor::new(bytes).read_string().unwrap_err();
        assert!(matches!(error, crate::Error::Utf16(_)));
    }

    #[test]
    fn minimum_i32_fstring_length_is_rejected_without_negation_overflow() {
        let mut bytes = Vec::new();
        bytes.write_i32::<LE>(i32::MIN).unwrap();

        let error = Cursor::new(bytes).read_string().unwrap_err();
        assert!(matches!(error, crate::Error::Other(_)));
    }

    #[test]
    fn impossible_untrusted_lengths_return_errors_instead_of_panicking() {
        let mut input = Cursor::new(Vec::<u8>::new());
        assert!(input.read_len(usize::MAX).is_err());

        let mut input = Cursor::new(Vec::<u8>::new());
        let result = input.read_array_len::<u16>(usize::MAX, |_| Ok(0));
        assert!(result.is_err());
    }
}
