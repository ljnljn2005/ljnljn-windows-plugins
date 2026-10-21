//! 合成 hive 构造器——**仅供单元测试使用**(`#[cfg(test)]`)。
//!
//! 合成 SYSTEM hive 构造器，仅供单元测试使用。
//! 数据全部由测试参数生成，与任何真实案件无关。


const HBIN_START: usize = 0x20;

/// hive 里的一个键:名称 + 类名 + 值 + 子键
pub struct KeySpec {
    pub name: String,
    pub class: Option<Vec<u8>>,
    pub last_write: u64,
    pub values: Vec<(String, u32, Vec<u8>)>,
    pub children: Vec<KeySpec>,
}

impl KeySpec {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            class: None,
            last_write: 0,
            values: Vec::new(),
            children: Vec::new(),
        }
    }

    pub fn child(mut self, child: KeySpec) -> Self {
        self.children.push(child);
        self
    }

    pub fn last_write(mut self, filetime: u64) -> Self {
        self.last_write = filetime;
        self
    }

    pub fn class(mut self, class: Vec<u8>) -> Self {
        self.class = Some(class);
        self
    }

    pub fn value(mut self, name: &str, kind: u32, data: Vec<u8>) -> Self {
        self.values.push((name.to_string(), kind, data));
        self
    }
}

fn cell_size(payload: usize) -> usize {
    (payload + 8).div_ceil(8) * 8
}

#[derive(Clone, Copy, Debug)]
struct CellSpec {
    offset: usize,
    length: usize,
}

struct Builder {
    hbins: Vec<u8>,
    next: usize,
}

impl Builder {
    fn new() -> Self {
        Self {
            hbins: Vec::new(),
            next: HBIN_START,
        }
    }

    fn allocate(&mut self, payload: usize) -> CellSpec {
        let length = cell_size(payload);
        let offset = self.next;
        self.hbins.resize(offset + length, 0);
        self.next = offset + length;
        CellSpec { offset, length }
    }

    fn write_cell(&mut self, cell: CellSpec, payload: &[u8]) {
        let length = cell.length as i32;
        self.hbins[cell.offset..cell.offset + 4].copy_from_slice(&length.to_le_bytes());
        self.hbins[cell.offset + 4..cell.offset + 4 + payload.len()].copy_from_slice(payload);
        let tail = cell.offset + cell.length - 4;
        self.hbins[tail..tail + 4].copy_from_slice(&length.to_le_bytes());
    }

    fn build_key(&mut self, spec: &KeySpec) -> u64 {
        let name_bytes = utf16_bytes(&spec.name);
        let cell = self.allocate(0x4C + name_bytes.len());
        let class_cell = match spec.class.as_ref().filter(|class| !class.is_empty()) {
            Some(class) => {
                let inner = self.allocate(class.len());
                self.write_cell(inner, class);
                Some((inner, class.len()))
            }
            None => None,
        };
        let sub_offsets: Vec<u32> = spec
            .children
            .iter()
            .map(|child| {
                let cell = self.build_key(child);
                cell as u32
            })
            .collect();
        let sub_list = if sub_offsets.is_empty() {
            None
        } else {
            let mut data = vec![0u8; 4 + sub_offsets.len() * 4];
            data[0..2].copy_from_slice(b"lf");
            data[2..4].copy_from_slice(&(sub_offsets.len() as u16).to_le_bytes());
            for (index, offset) in sub_offsets.iter().enumerate() {
                data[4 + index * 4..8 + index * 4].copy_from_slice(&offset.to_le_bytes());
            }
            let list = self.allocate(data.len());
            self.write_cell(list, &data);
            Some(list)
        };
        let mut value_offsets = Vec::new();
        for (name, kind, payload) in &spec.values {
            let value_name = utf16_bytes(name);
            let inline = payload.len() <= 4;
            let data_cell = if inline || payload.is_empty() {
                None
            } else {
                let inner = self.allocate(payload.len());
                self.write_cell(inner, payload);
                Some(inner)
            };
            let inline_extra = if inline { payload.len() } else { 0 };
            let value_cell = self.allocate(0x14 + value_name.len() + inline_extra);
            let mut cell_payload = vec![0u8; 0x14 + value_name.len() + inline_extra];
            cell_payload[0..2].copy_from_slice(&0x6B76u16.to_le_bytes()); // "vk"
            cell_payload[2..4].copy_from_slice(&(value_name.len() as u16).to_le_bytes());
            let stored_len = if inline {
                (payload.len() as u32) | 0x8000_0000
            } else {
                payload.len() as u32
            };
            cell_payload[4..8].copy_from_slice(&stored_len.to_le_bytes());
            match data_cell {
                Some(inner) => {
                    cell_payload[8..0xC].copy_from_slice(&(inner.offset as u32).to_le_bytes())
                }
                None => cell_payload[8..0xC].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()),
            }
            cell_payload[0xC..0x10].copy_from_slice(&kind.to_le_bytes());
            cell_payload[0x10..0x12].copy_from_slice(&1u16.to_le_bytes());
            cell_payload[0x14..0x14 + value_name.len()].copy_from_slice(&value_name);
            if inline && !payload.is_empty() {
                let at = 0x14 + value_name.len();
                cell_payload[at..at + payload.len()].copy_from_slice(payload);
            }
            self.write_cell(value_cell, &cell_payload);
            value_offsets.push(value_cell.offset as u32);
        }
        let value_list = if value_offsets.is_empty() {
            None
        } else {
            let mut data = Vec::new();
            for offset in &value_offsets {
                data.extend_from_slice(&offset.to_le_bytes());
            }
            let list = self.allocate(data.len());
            self.write_cell(list, &data);
            Some(list)
        };

        let mut payload = vec![0u8; 0x4C + name_bytes.len()];
        payload[0..2].copy_from_slice(&0x6B6Eu16.to_le_bytes()); // "nk"
        payload[2..4].copy_from_slice(&0x2C20u16.to_le_bytes());
        payload[4..12].copy_from_slice(&spec.last_write.to_le_bytes());
        if let Some(list) = &sub_list {
            payload[0x14..0x18].copy_from_slice(&(sub_offsets.len() as u32).to_le_bytes());
            payload[0x1C..0x20].copy_from_slice(&(list.offset as u32).to_le_bytes());
        }
        if let Some(list) = &value_list {
            payload[0x24..0x28].copy_from_slice(&(value_offsets.len() as u32).to_le_bytes());
            payload[0x28..0x2C].copy_from_slice(&(list.offset as u32).to_le_bytes());
        }
        payload[0x38..0x3C].copy_from_slice(&64u32.to_le_bytes());
        payload[0x3C..0x40].copy_from_slice(&1024u32.to_le_bytes());
        payload[0x48..0x4A].copy_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        match class_cell {
            Some((offset, len)) => {
                let offset = offset.offset;
                payload[0x2C..0x30].copy_from_slice(&(offset as u32).to_le_bytes());
                payload[0x4A..0x4C].copy_from_slice(&(len as u16).to_le_bytes());
            }
            None => payload[0x2C..0x30].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()),
        }
        payload[0x4C..].copy_from_slice(&name_bytes);
        self.write_cell(cell, &payload);
        cell.offset as u64
    }

    fn finish(self) -> Vec<u8> {
        let hbin_size = ((self.hbins.len() + 0xFFF) & !0xFFF).max(0x1000);
        let mut hbins = self.hbins;
        hbins.resize(hbin_size, 0);
        let free_start = self.next;
        if free_start + 8 <= hbin_size {
            let free_len = (hbin_size - free_start) as i32;
            hbins[free_start..free_start + 4].copy_from_slice(&free_len.to_le_bytes());
            hbins[hbin_size - 4..hbin_size].copy_from_slice(&free_len.to_le_bytes());
        }
        hbins[0..4].copy_from_slice(b"hbin");
        // hbin 的“相对偏移”字段以首个 hbin 为 0（真实 hive 的首个 hbin 写 0）。
        hbins[4..8].copy_from_slice(&0u32.to_le_bytes());
        hbins[8..0xC].copy_from_slice(&(hbin_size as u32).to_le_bytes());
        let mut file = vec![0u8; 0x1000];
        file[0..4].copy_from_slice(b"regf");
        file[4..8].copy_from_slice(&1u32.to_le_bytes());
        file[8..0xC].copy_from_slice(&1u32.to_le_bytes());
        file[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
        file[0x18..0x1C].copy_from_slice(&5u32.to_le_bytes());
        file[0x1C..0x20].copy_from_slice(&0u32.to_le_bytes());
        file[0x20..0x24].copy_from_slice(&1u32.to_le_bytes());
        file[0x24..0x28].copy_from_slice(&1u32.to_le_bytes());
        file[0x28..0x2C].copy_from_slice(&(hbin_size as u32).to_le_bytes());
        file[0x2C..0x30].copy_from_slice(&1u32.to_le_bytes());
        file.extend_from_slice(&hbins);
        file
    }
}

pub fn utf16_bytes(text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for unit in text.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

/// 用根键规格构造完整 hive 字节流。
pub fn build_hive(root: &KeySpec) -> Vec<u8> {
    let mut builder = Builder::new();
    let root_offset = builder.build_key(root);
    let mut bytes = builder.finish();
    bytes[0x24..0x28].copy_from_slice(&(root_offset as u32).to_le_bytes());
    bytes
}

