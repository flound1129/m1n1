// SPDX-License-Identifier: GPL-2.0-or-later
use core::ffi::*;
use core::mem::size_of;

use crate::c_size_t;

#[derive(Debug)]
pub enum AdtError {
    NotFound = -1,
    BadOffset = -4,
    BadPath = -5,
    BadNCells = -14,
    BadValue = -15,
    BadLength = -20,
}

const ADT_ALIGN: usize = 4;
const ADT_MAX_DEPTH: usize = 8;
const ADT_SIZE_MASK: u32 = 0x7fff_ffff;
const ADT_NODE_HEADER_SIZE: usize = size_of::<ADTNode>();
const ADT_PROPERTY_HEADER_SIZE: usize = size_of::<[c_char; 32]>() + size_of::<u32>();

/// An ADT node consists of a header (the part described by the struct), packed
/// key:value properties, and subnodes. Properties are always before subnodes
/// in memory.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ADTNode {
    property_count: u32,
    child_count: u32,
}

/// An ADT property is simply a collection of bytes preceded by a header which
/// denotes its name and size in bytes (exclusive of the header).
#[repr(C)]
#[derive(Debug)]
pub struct ADTProperty {
    name: [c_char; 32],
    size: u32,
    value: [u8],
}

/// ADTPropertyStringIterator
#[derive(Debug)]
pub struct ADTPropertyStringIterator<'a> {
    value: &'a [u8],
}

impl<'a> Iterator for ADTPropertyStringIterator<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<&'a str> {
        match CStr::from_bytes_until_nul(self.value) {
            Ok(cs) => match cs.to_str() {
                Ok(s) => {
                    match self.value.iter().position(|&x| x == 0) {
                        Some(nul) => self.value = &self.value[(nul + 1)..],
                        None => self.value = &[],
                    }
                    Some(s)
                }
                Err(_) => {
                    self.value = &[];
                    None
                }
            },
            Err(_) => {
                self.value = &[];
                None
            }
        }
    }
}

/// ADTPropertiesIterator
#[derive(Debug)]
pub struct ADTPropertiesIterator {
    next_property_res: Option<Result<&'static ADTProperty, AdtError>>,
    remaining: usize,
}

impl Iterator for ADTPropertiesIterator {
    type Item = Result<&'static ADTProperty, AdtError>;

    fn next(&mut self) -> Option<Result<&'static ADTProperty, AdtError>> {
        let Some(property_res) = self.next_property_res.take() else {
            return None;
        };
        let remaining = core::mem::take(&mut self.remaining);
        let property = match property_res {
            Err(e) => return Some(Err(e)),
            Ok(v) => v,
        };

        if remaining > 1 {
            self.next_property_res = Some(property.next_property());
            self.remaining = remaining - 1;
        }

        Some(Ok(property))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for ADTPropertiesIterator {}

/// ADTPropertiesIteratorMut
#[derive(Debug)]
pub struct ADTPropertiesIteratorMut {
    next_property_res: Option<Result<&'static mut ADTProperty, AdtError>>,
    remaining: usize,
}

impl Iterator for ADTPropertiesIteratorMut {
    type Item = Result<&'static mut ADTProperty, AdtError>;

    fn next(&mut self) -> Option<Result<&'static mut ADTProperty, AdtError>> {
        let Some(property_res) = self.next_property_res.take() else {
            return None;
        };
        let remaining = core::mem::take(&mut self.remaining);
        let property = match property_res {
            Err(e) => return Some(Err(e)),
            Ok(v) => v,
        };

        if remaining > 1 {
            self.next_property_res = Some(property.next_property_mut());
            self.remaining = remaining - 1;
        }

        Some(Ok(property))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for ADTPropertiesIteratorMut {}

#[repr(C, packed(1))]
pub struct ADTSegmentRanges {
    phys: u64,
    iova: u64,
    remap: u64,
    size: u32,
    unk: u32,
}

/// Check that our address is properly aligned
fn check_ptr(ptr: usize) -> Result<(), AdtError> {
    if ptr == 0 || ptr % ADT_ALIGN != 0 {
        Err(AdtError::BadOffset)
    } else {
        Ok(())
    }
}

/// Return a byte range in the one boot-time ADT extent.  In particular, do
/// not form the pointer until both the offset and length have been checked:
/// callers pass offsets from C and a negative offset must never become a huge
/// `usize` for `add`.
fn adt_range(offset: usize, len: usize) -> Result<*mut u8, AdtError> {
    let base = unsafe { adt as *mut u8 };
    check_ptr(base as usize)?;
    let extent = unsafe { adt_get_size() as usize };
    if extent > isize::MAX as usize || offset > extent || len > extent - offset {
        return Err(AdtError::BadOffset);
    }
    let end = (base as usize)
        .checked_add(extent)
        .ok_or(AdtError::BadOffset)?;
    if end < base as usize {
        return Err(AdtError::BadOffset);
    }
    // `offset <= extent <= isize::MAX` makes this add representable as a
    // pointer offset; the checked address sum above rules out wrapping.
    let ptr = unsafe { base.add(offset) };
    check_ptr(ptr as usize)?;
    Ok(ptr)
}

fn adt_offset_from_ptr(ptr: *const u8) -> Result<usize, AdtError> {
    check_ptr(ptr as usize)?;
    let base = unsafe { adt as *const u8 } as usize;
    let addr = ptr as usize;
    let offset = addr.checked_sub(base).ok_or(AdtError::BadOffset)?;
    let _ = adt_range(offset, 0)?;
    Ok(offset)
}

fn adt_offset_from_c(offset: c_int) -> Result<usize, AdtError> {
    if offset < 0 {
        return Err(AdtError::BadOffset);
    }
    Ok(offset as usize)
}

fn adt_offset_to_c(ptr: *const u8) -> Result<c_int, AdtError> {
    let offset = adt_offset_from_ptr(ptr)?;
    offset.try_into().map_err(|_| AdtError::BadOffset)
}

fn checked_record_len(payload: usize) -> Result<usize, AdtError> {
    let padded = payload
        .checked_add(ADT_ALIGN - 1)
        .ok_or(AdtError::BadLength)?
        & !(ADT_ALIGN - 1);
    ADT_PROPERTY_HEADER_SIZE
        .checked_add(padded)
        .ok_or(AdtError::BadLength)
}

fn property_record(offset: usize) -> Result<(usize, usize), AdtError> {
    let ptr = adt_range(offset, ADT_PROPERTY_HEADER_SIZE)?;
    let raw_size = unsafe { u32::from_le(core::ptr::read_unaligned(ptr.add(32).cast::<u32>())) };
    // Preserve the existing wire policy: payloads are below 1 MiB, while
    // bit 31 is a template marker and is excluded from the payload length.
    if raw_size & 0x7ff0_0000 != 0 {
        return Err(AdtError::BadOffset);
    }
    let payload = (raw_size & ADT_SIZE_MASK) as usize;
    let record_len = checked_record_len(payload)?;
    let _ = adt_range(offset, record_len)?;
    Ok((payload, record_len))
}

/// Determine if an ADT node's name is equal to some string bounded by a length.
/// This is required to match the semantics expected when doing a full ADT path
/// trace.
fn node_names_equal(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }

    if b.contains('@') && a.as_bytes().get(b.len()) == Some(&b'@') {
        return true;
    }

    false
}

fn get_cells(src: &[u32]) -> u64 {
    let mut val: u64 = 0;

    src.iter()
        .enumerate()
        .for_each(|(i, &x)| val |= (x as u64) << (32 * i));

    val
}

fn get_cells_u8(src: &[u8]) -> u64 {
    let mut val: u64 = 0;

    for chunk in src.rchunks_exact(4) {
        val = (val << 32) | (u32::from_le_bytes(chunk.try_into().unwrap()) as u64)
    }

    val
}

/// Retrieve the register container (addr, size) of a given node at the end of
/// a node path trace.
///
/// Each addr and size is a contiguous array of u32s with `#address-cells` or
/// `#size-cells` elements. The entire `reg` property is similarly a contiguous
/// array of these containers [(addr, size), (addr, size), ...]. The `i` argument
/// is an index into this array.
pub fn get_reg_container(
    nodes: &[Option<&'static ADTNode>],
    pname: &str,
    i: i32,
) -> Result<(u64, u64), AdtError> {
    if nodes.is_empty() || i < 0 {
        return Err(AdtError::BadPath);
    }
    let head = ADTNode::root()?;

    // Sanity check to make sure we have at least one node in the path
    if nodes[0].is_none() {
        return Err(AdtError::BadPath);
    }

    if nodes[0].unwrap().as_ptr() == unsafe { adt as *const u8 } {
        return Err(AdtError::BadOffset);
    }

    let mut cursor: usize = nodes.len() - 1;

    while cursor > 0 && nodes[cursor].is_none() {
        cursor -= 1;
    }

    if nodes[cursor].is_none() {
        return Err(AdtError::BadPath);
    }

    let mut node = nodes[cursor].unwrap();

    let mut parent = {
        if cursor > 0 {
            nodes[cursor - 1].unwrap()
        } else {
            head
        }
    };

    let mut addr_cells = parent.named_prop("#address-cells")?.u32()?;

    let mut size_cells = parent.named_prop("#size-cells")?.u32()?;

    if addr_cells < 1 || addr_cells > 2 || size_cells > 2 {
        return Err(AdtError::BadNCells);
    }

    let reg = node.named_prop(pname)?;

    if reg.payload_size() == 0 {
        return Err(AdtError::NotFound);
    }

    // Check that the reg property is big enough to contain a reg
    // container at index i.
    let cells = (addr_cells as usize)
        .checked_add(size_cells as usize)
        .ok_or(AdtError::BadValue)?;
    let required = (i as usize)
        .checked_add(1)
        .and_then(|n| n.checked_mul(cells))
        .and_then(|n| n.checked_mul(size_of::<u32>()))
        .ok_or(AdtError::BadValue)?;
    if (reg.payload_size() as usize) < required {
        return Err(AdtError::BadValue);
    }

    let addr_elems: &[u32];
    let size_elems: &[u32];

    // SAFETY: For a reg property, this pointer arithmetic is always true,
    // as we check above that i is within bounds.
    let start = (i as usize).checked_mul(cells).ok_or(AdtError::BadValue)?;
    let words: &[u32] = unsafe {
        core::slice::from_raw_parts(
            reg.value.as_ptr() as *const u32,
            reg.value.len() / size_of::<u32>(),
        )
    };
    addr_elems = &words[start..start + addr_cells as usize];
    size_elems = &words[start + addr_cells as usize..start + cells];

    let mut addr = get_cells(addr_elems);
    let size = get_cells(size_elems);

    while parent.as_ptr() != head.as_ptr() {
        cursor -= 1;
        node = parent;
        parent = {
            if cursor > 0 {
                nodes[cursor - 1].unwrap()
            } else {
                head
            }
        };

        let ranges = match node.named_prop("ranges") {
            Ok(r) => r,
            Err(AdtError::NotFound) => break,
            Err(e) => return Err(e),
        };

        let paddr_cells = parent.named_prop("#address-cells")?.u32()?;

        if paddr_cells < 1 || paddr_cells > 2 || size_cells > 2 {
            return Err(AdtError::BadNCells);
        }

        let entry_words = (paddr_cells as usize)
            .checked_add(addr_cells as usize)
            .and_then(|n| n.checked_add(size_cells as usize))
            .ok_or(AdtError::BadValue)?;
        let entry_size = size_of::<u32>()
            .checked_mul(entry_words)
            .ok_or(AdtError::BadValue)?;
        // An empty ranges property is the valid identity-mapping form.  A
        // nonempty property must contain at least one complete entry.
        if entry_size == 0 || (!ranges.value.is_empty() && ranges.value.len() < entry_size) {
            return Err(AdtError::BadValue);
        }
        let slice: &[u8] = &ranges.value[..];

        for range in slice.chunks_exact(entry_size) {
            let (ca_ref, remainder) = range.split_at(4 * addr_cells as usize);
            let (pa_ref, cs_ref) = remainder.split_at(4 * paddr_cells as usize);

            let child_addr = get_cells_u8(ca_ref);
            let parent_addr = get_cells_u8(pa_ref);
            let child_size = get_cells_u8(cs_ref);

            let addr_end = addr.checked_add(size).ok_or(AdtError::BadValue)?;
            let child_end = child_addr
                .checked_add(child_size)
                .ok_or(AdtError::BadValue)?;
            if addr >= child_addr && addr_end <= child_end {
                addr = addr
                    .checked_sub(child_addr)
                    .and_then(|v| v.checked_add(parent_addr))
                    .ok_or(AdtError::BadValue)?;
                break;
            }
        }

        size_cells = parent.named_prop("#size-cells")?.u32()?;

        addr_cells = paddr_cells;
    }

    Ok((addr, size))
}

impl ADTNode {
    /// Check that the node pointed to is within the bounds of the ADT and
    /// has a valid property and child count
    fn from_offset(offset: usize) -> Result<&'static ADTNode, AdtError> {
        let ptr = adt_range(offset, ADT_NODE_HEADER_SIZE)? as *const ADTNode;
        let property_count = unsafe { u32::from_le(core::ptr::read_unaligned(ptr.cast())) };
        let child_count =
            unsafe { u32::from_le(core::ptr::read_unaligned(ptr.cast::<u8>().add(4).cast())) };
        if property_count > 2048 || property_count == 0 || child_count > 2048 {
            return Err(AdtError::BadOffset);
        }
        // The header has been range-checked before constructing the reference.
        Ok(unsafe { &*ptr })
    }

    /// Get a reference to the root node
    pub fn root() -> Result<&'static ADTNode, AdtError> {
        ADTNode::from_offset(0)
    }

    /// Get a reference to a node at a specified path, tracing the path to the
    /// desired node
    pub fn from_path_trace(
        path: &str,
        mut breadcrumbs: Option<&mut [Option<&'static ADTNode>]>,
    ) -> Result<&'static ADTNode, AdtError> {
        let mut p = path;
        let mut bc_idx: usize = 0;

        let head = ADTNode::root()?;
        let mut n = head;

        while !p.is_empty() {
            p = p.trim_start_matches('/');

            if p.is_empty() {
                break;
            }

            let (cursor, rest) = match p.find('/') {
                Some(pos) => p.split_at(pos),
                None => (p, ""),
            };

            match n.subnode_by_name(cursor) {
                Ok(sn) => {
                    n = sn;
                }
                Err(e) => {
                    if let Some(b) = breadcrumbs.as_mut() {
                        if bc_idx < b.len() {
                            b[bc_idx] = Some(head);
                        } else {
                            return Err(AdtError::BadPath);
                        }
                    }
                    return Err(e);
                }
            };

            if let Some(b) = breadcrumbs.as_mut() {
                if bc_idx < b.len() {
                    b[bc_idx] = Some(n);
                    bc_idx += 1;
                } else {
                    return Err(AdtError::BadPath);
                }
            }

            p = rest;
        }

        Ok(n)
    }

    pub fn from_path(path: &str) -> Result<&'static ADTNode, AdtError> {
        ADTNode::from_path_trace(path, None)
    }

    pub fn as_ptr(&self) -> *const u8 {
        self as *const ADTNode as *const u8
    }

    pub fn first_property(&self) -> Result<&'static ADTProperty, AdtError> {
        // SAFETY: We can never have a node that does not have at least one
        // property, and that property is always at the byte immediately following
        // the node header.
        let node_offset = adt_offset_from_ptr(self.as_ptr())?;
        let property_offset = node_offset
            .checked_add(ADT_NODE_HEADER_SIZE)
            .ok_or(AdtError::BadOffset)?;
        ADTProperty::from_offset(property_offset)
    }

    pub fn first_property_mut(&self) -> Result<&'static mut ADTProperty, AdtError> {
        // SAFETY: We know we are a valid node, and our header never changes size
        let node_offset = adt_offset_from_ptr(self.as_ptr())?;
        let property_offset = node_offset
            .checked_add(ADT_NODE_HEADER_SIZE)
            .ok_or(AdtError::BadOffset)?;
        ADTProperty::from_offset_mut(property_offset)
    }

    pub fn properties(&self) -> ADTPropertiesIterator {
        ADTPropertiesIterator {
            next_property_res: Some(self.first_property()),
            remaining: self.property_count as usize,
        }
    }

    pub fn properties_mut(&self) -> ADTPropertiesIteratorMut {
        ADTPropertiesIteratorMut {
            next_property_res: Some(self.first_property_mut()),
            remaining: self.property_count as usize,
        }
    }

    /// Walk the properties at the top of the curret node's memory to arrive at
    /// the node immediately following it. This could be a child node or a sibling.
    /// Use the relevant wrappers for additional safety.
    fn next_node(&self) -> Result<&'static ADTNode, AdtError> {
        let p = self.properties()
            .last()
            .unwrap() // There is always at least the first property, or an error
            ?;

        // SAFETY: We will only ever reach this code when we can guarantee that
        // p is a reference to the very last property of the node, meaning that
        // the next byte after it must be a node.
        let property_offset = adt_offset_from_ptr(p.as_ptr())?;
        let (_, record_len) = property_record(property_offset)?;
        let node_offset = property_offset
            .checked_add(record_len)
            .ok_or(AdtError::BadOffset)?;
        ADTNode::from_offset(node_offset)
    }

    /// Walk the properties at the top of the curret node's memory to arrive at
    /// the first child node of the current node
    pub fn first_child(&self) -> Result<&'static ADTNode, AdtError> {
        if self.child_count < 1 {
            return Err(AdtError::NotFound);
        }

        self.next_node()
    }

    /// Searches the node for a property with the given name, and returns it if
    /// found.
    pub fn named_prop(&self, name: &str) -> Result<&'static ADTProperty, AdtError> {
        for p in self.properties() {
            let p = p?;
            if p.name() == name {
                return Ok(p);
            }
        }
        Err(AdtError::NotFound)
    }

    pub fn name(&self) -> Result<&str, AdtError> {
        self.named_prop("name")?.str()
    }

    /// Searches the node for a property with the given name, and returns a mutable
    /// reference to it if found.
    pub fn named_prop_mut(&self, name: &str) -> Result<&'static mut ADTProperty, AdtError> {
        for p in self.properties_mut() {
            let p = p?;
            if p.name() == name {
                return Ok(p);
            }
        }
        Err(AdtError::NotFound)
    }

    /// Returns a reference to the current node's closest sibling
    pub fn next_sibling(&self) -> Result<&'static ADTNode, AdtError> {
        if self.child_count < 1 {
            return self.next_node();
        }

        let mut c = self.first_child()?;

        for _ in 0..self.child_count {
            c = c.next_sibling()?;
        }
        Ok(c)
    }

    /// Walks the node's subnodes and searches for one with the specified name
    pub fn subnode_by_name(&self, name: &str) -> Result<&'static ADTNode, AdtError> {
        let mut c = self.first_child()?;

        for _ in 0..self.child_count {
            let prop = c.named_prop("name")?;
            if node_names_equal(prop.str()?, name) {
                return Ok(c);
            }
            c = c.next_sibling()?;
        }
        Err(AdtError::NotFound)
    }

    pub fn is_compatible(&self, compatible: &str) -> Result<bool, AdtError> {
        match self.named_prop("compatible") {
            Ok(prop) => Ok(prop.str_iter().any(|c| c == compatible)),
            Err(AdtError::NotFound) => Ok(false),
            Err(e) => Err(e),
        }
    }

    pub fn compatible(&self, index: usize) -> Option<&str> {
        let prop = self.named_prop("compatible").ok()?;
        prop.str_iter().nth(index)
    }
}

impl ADTProperty {
    fn payload_size(&self) -> u32 {
        self.size & ADT_SIZE_MASK
    }

    /// Create a Rust fat pointer to the ADTProperty at ptr.
    ///
    /// We need to do this manually since we do not know the size of
    /// ADTProperty.value beforehand.
    fn fat_ptr(ptr: *const u8, size: usize) -> *mut ADTProperty {
        // A pointer to a struct with a slice tail carries the tail length, not
        // the size of the header plus the tail.
        let sp: *const [u8] = core::ptr::slice_from_raw_parts(ptr, size);
        sp as *mut ADTProperty
    }

    /// Check that our property is no bigger than 1 MB
    /// Validate the complete physical record before constructing its DST.
    fn from_offset(offset: usize) -> Result<&'static ADTProperty, AdtError> {
        let (payload, _) = property_record(offset)?;
        let ptr = adt_range(offset, ADT_PROPERTY_HEADER_SIZE)? as *const u8;
        let prop = ADTProperty::fat_ptr(ptr, payload);
        Ok(unsafe { &*prop })
    }

    fn from_offset_mut(offset: usize) -> Result<&'static mut ADTProperty, AdtError> {
        let (payload, _) = property_record(offset)?;
        let ptr = adt_range(offset, ADT_PROPERTY_HEADER_SIZE)? as *const u8;
        let prop = ADTProperty::fat_ptr(ptr, payload);
        Ok(unsafe { &mut *prop })
    }

    pub fn as_ptr(&self) -> *const u8 {
        self as *const ADTProperty as *const u8
    }

    pub fn next_property(&self) -> Result<&'static ADTProperty, AdtError> {
        let offset = adt_offset_from_ptr(self.as_ptr())?;
        let (_, record_len) = property_record(offset)?;
        ADTProperty::from_offset(offset.checked_add(record_len).ok_or(AdtError::BadOffset)?)
    }

    pub fn next_property_mut(&self) -> Result<&'static mut ADTProperty, AdtError> {
        let offset = adt_offset_from_ptr(self.as_ptr())?;
        let (_, record_len) = property_record(offset)?;
        ADTProperty::from_offset_mut(offset.checked_add(record_len).ok_or(AdtError::BadOffset)?)
    }

    pub fn name(&self) -> &str {
        // The wire field is bytes; `c_char` is signed on several Rust
        // targets, so view it explicitly as bytes before CStr parsing.
        let name = unsafe {
            core::slice::from_raw_parts(self.name.as_ptr() as *const u8, self.name.len())
        };
        CStr::from_bytes_until_nul(name).unwrap().to_str().unwrap()
    }

    pub fn str(&self) -> Result<&str, AdtError> {
        match CStr::from_bytes_until_nul(&self.value) {
            Ok(cs) => match cs.to_str() {
                Ok(s) => Ok(s),
                Err(_e) => Err(AdtError::BadValue),
            },
            Err(_e) => Err(AdtError::BadValue),
        }
    }

    pub fn str_iter<'a>(&'a self) -> ADTPropertyStringIterator<'a> {
        ADTPropertyStringIterator {
            value: unsafe {
                core::slice::from_raw_parts(self.value.as_ptr(), self.payload_size() as usize)
            },
        }
    }

    pub fn set(&mut self, val: &[u8]) -> Result<usize, AdtError> {
        let size = self.payload_size() as usize;
        if val.len() != size {
            return Err(AdtError::BadLength);
        }

        unsafe {
            core::ptr::copy_nonoverlapping(val.as_ptr(), self.value.as_mut_ptr(), size);
        }

        Ok(size)
    }

    /// Copy an ADTProperty's value to a preallocated buffer
    pub fn copy_raw(&self, ptr: usize) -> Result<usize, AdtError> {
        // SAFETY: Callers are reponsible for allocating self.payload_size() bytes at ptr,
        // and we never reach this code if we aren't already certain that we are
        // a valid property
        unsafe {
            core::ptr::copy_nonoverlapping(
                self.value.as_ptr(),
                ptr as *mut u8,
                self.payload_size() as usize,
            );
        }

        Ok(self.payload_size() as usize)
    }

    pub fn u32(&self) -> Result<u32, AdtError> {
        if self.payload_size() != 4 {
            return Err(AdtError::BadLength);
        }

        Ok(u32::from_ne_bytes(self.value[..4].try_into().unwrap()))
    }

    pub fn u64(&self) -> Result<u64, AdtError> {
        if self.payload_size() != 8 {
            return Err(AdtError::BadLength);
        }

        Ok(u64::from_ne_bytes(self.value[..8].try_into().unwrap()))
    }
}

extern "C" {
    static adt: *const c_void; // Global, immutable
}

unsafe extern "C" {
    unsafe fn adt_get_size() -> c_uint;
}

#[no_mangle]
pub unsafe extern "C" fn adt_check_header(_dt: *const c_void) -> c_int {
    match ADTNode::root() {
        Ok(_) => 0,
        Err(e) => e as c_int,
    }
}

fn node_from_c_offset(offset: c_int) -> Result<&'static ADTNode, AdtError> {
    ADTNode::from_offset(adt_offset_from_c(offset)?)
}

fn property_from_c_offset(offset: c_int) -> Result<&'static ADTProperty, AdtError> {
    ADTProperty::from_offset(adt_offset_from_c(offset)?)
}

#[no_mangle]
pub unsafe extern "C" fn adt_first_property_offset(_dt: *const c_void, offset: c_int) -> c_int {
    match node_from_c_offset(offset).and_then(|n| n.first_property()) {
        Ok(p) => adt_offset_to_c(p.as_ptr()).unwrap_or(AdtError::BadOffset as c_int),
        Err(e) => e as c_int,
    }
}

// Preserve the C API's record-end behavior: this returns the checked end of
// the current record even when it is the next node or one-past the ADT.
#[no_mangle]
pub unsafe extern "C" fn adt_next_property_offset(_dt: *const c_void, offset: c_int) -> c_int {
    let offset = match adt_offset_from_c(offset) {
        Ok(v) => v,
        Err(e) => return e as c_int,
    };
    let (_, record_len) = match property_record(offset) {
        Ok(v) => v,
        Err(e) => return e as c_int,
    };
    let next = match offset.checked_add(record_len) {
        Some(v) => v,
        None => return AdtError::BadOffset as c_int,
    };
    match adt_range(next, 0) {
        Ok(_) => next.try_into().unwrap_or(AdtError::BadOffset as c_int),
        Err(e) => e as c_int,
    }
}

#[no_mangle]
pub unsafe extern "C" fn adt_first_child_offset(_dt: *const c_void, offset: c_int) -> c_int {
    let child = match node_from_c_offset(offset).and_then(|n| n.first_child()) {
        Ok(c) => c,
        Err(e) => return e as c_int,
    };
    adt_offset_to_c(child.as_ptr()).unwrap_or(AdtError::BadOffset as c_int)
}

#[no_mangle]
pub unsafe extern "C" fn adt_next_sibling_offset(_dt: *const c_void, offset: c_int) -> c_int {
    match node_from_c_offset(offset).and_then(|n| n.next_sibling()) {
        Ok(n) => adt_offset_to_c(n.as_ptr()).unwrap_or(AdtError::BadOffset as c_int),
        Err(e) => e as c_int,
    }
}

#[no_mangle]
pub unsafe extern "C" fn adt_get_child_count(_dt: *const c_void, offset: c_int) -> c_int {
    match node_from_c_offset(offset) {
        Ok(n) => n.child_count as c_int,
        Err(e) => e as c_int,
    }
}

#[no_mangle]
pub unsafe extern "C" fn adt_get_property_count(_dt: *const c_void, offset: c_int) -> c_int {
    match node_from_c_offset(offset) {
        Ok(n) => n.property_count as c_int,
        Err(e) => e as c_int,
    }
}

#[no_mangle]
pub unsafe extern "C" fn adt_get_property_by_offset(
    _dt: *const c_void,
    offset: c_int,
) -> *const c_void {
    match property_from_c_offset(offset) {
        Ok(p) => p as *const ADTProperty as *const c_void,
        Err(_) => core::ptr::null(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn adt_get_property(
    _dt: *const c_void,
    offset: c_int,
    name: *const c_char,
) -> *const c_void {
    let strname: &str = unsafe { CStr::from_ptr(name).to_str().unwrap() };
    let n = match node_from_c_offset(offset) {
        Ok(n) => n,
        Err(_) => return core::ptr::null(),
    };

    match n.named_prop(strname) {
        Ok(p) => p.as_ptr() as *const c_void,
        Err(_) => core::ptr::null(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn adt_getprop(
    _dt: *const c_void,
    offset: c_int,
    name: *const c_char,
    lenp: *mut c_uint,
) -> *const c_void {
    let strname: &str = unsafe { CStr::from_ptr(name).to_str().unwrap() };
    let n = match node_from_c_offset(offset) {
        Ok(n) => n,
        Err(_) => return core::ptr::null(),
    };
    let p = match n.named_prop(strname) {
        Ok(prop) => prop,
        Err(_) => return core::ptr::null(),
    };

    if !lenp.is_null() {
        unsafe { *lenp = p.payload_size() }
    }

    p.value.as_ptr() as *const c_void
}

#[no_mangle]
pub unsafe extern "C" fn adt_getprop_by_offset(
    _dt: *const c_void,
    offset: c_int,
    namep: *mut *const c_char,
    lenp: *mut c_uint,
) -> *const c_void {
    let p = match property_from_c_offset(offset) {
        Ok(prop) => prop,
        Err(_) => return core::ptr::null(),
    };

    if !namep.is_null() {
        unsafe { *namep = p.name.as_ptr() }
    }

    if !lenp.is_null() {
        unsafe { *lenp = p.payload_size() }
    }

    p.value.as_ptr() as *const c_void
}

#[no_mangle]
pub unsafe extern "C" fn adt_setprop(
    _dt: *const c_void,
    offset: c_int,
    name: *const c_char,
    val: *const c_void,
    len: *const c_size_t,
) -> c_int {
    let strname: &str = unsafe { CStr::from_ptr(name).to_str().unwrap() };
    let n = match node_from_c_offset(offset) {
        Ok(node) => node,
        Err(e) => return e as c_int,
    };

    // `val` and `len` are caller-owned C ABI inputs; ADT validation is done
    // first so a bad node offset cannot be used to reach this slice.
    let buf: &[u8] = unsafe { core::slice::from_raw_parts(val as *const u8, len as usize) };

    let p = match n.named_prop_mut(strname) {
        Ok(prop) => prop,
        Err(e) => return e as c_int,
    };

    match p.set(buf) {
        Ok(sz) => sz.try_into().unwrap(),
        Err(e) => e as c_int,
    }
}

#[no_mangle]
pub unsafe extern "C" fn adt_subnode_offset(
    _dt: *const c_void,
    offset: c_int,
    name: *const c_char,
) -> c_int {
    let strname: &str = unsafe { CStr::from_ptr(name).to_str().unwrap() };
    let n = match node_from_c_offset(offset) {
        Ok(node) => node,
        Err(e) => return e as c_int,
    };

    match n.subnode_by_name(strname) {
        Ok(s) => adt_offset_to_c(s.as_ptr()).unwrap_or(AdtError::BadOffset as c_int),
        Err(e) => e as c_int,
    }
}

#[no_mangle]
pub unsafe extern "C" fn adt_is_compatible(
    _dt: *const c_void,
    offset: c_int,
    compat: *const c_char,
) -> bool {
    let strcompat: &str = unsafe { CStr::from_ptr(compat).to_str().unwrap() };
    match node_from_c_offset(offset).and_then(|n| n.is_compatible(strcompat)) {
        Ok(v) => v,
        Err(_) => false,
    }
}

#[no_mangle]
pub unsafe extern "C" fn adt_is_compatible_at(
    _dt: *const c_void,
    offset: c_int,
    compat: *const c_char,
    index: usize,
) -> bool {
    let strcompat: &str = unsafe { CStr::from_ptr(compat).to_str().unwrap() };
    match node_from_c_offset(offset) {
        Ok(n) => n.compatible(index) == Some(strcompat),
        Err(_) => false,
    }
}

#[no_mangle]
pub unsafe extern "C" fn adt_get_name(_dt: *const c_void, offset: c_int) -> *const c_char {
    match node_from_c_offset(offset).and_then(|n| n.name()) {
        Ok(name) => name.as_ptr() as *const c_char,
        Err(_) => core::ptr::null(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn adt_getprop_copy(
    _dt: *const c_void,
    offset: c_int,
    name: *const c_char,
    out: *mut c_void,
    len: c_size_t,
) -> c_int {
    let strname: &str = unsafe { CStr::from_ptr(name).to_str().unwrap() };
    let n = match node_from_c_offset(offset) {
        Ok(node) => node,
        Err(e) => return e as c_int,
    };

    let p = match n.named_prop(strname) {
        Ok(prop) => prop,
        Err(e) => return e as c_int,
    };

    if p.payload_size() as usize != len {
        return AdtError::BadLength as c_int;
    }
    if len == 0 {
        return 0;
    }

    match p.copy_raw(out as usize) {
        Ok(l) => {
            if l != len {
                return AdtError::BadLength as c_int;
            } else {
                return len as c_int;
            }
        }
        Err(e) => e as c_int,
    }
}

#[no_mangle]
pub unsafe extern "C" fn adt_path_offset_trace(
    _dt: *const c_void,
    path: *const c_char,
    offsets: *mut i32,
) -> c_int {
    let strpath: &str = unsafe { CStr::from_ptr(path).to_str().unwrap() };

    // We don't know how deep the path will be, but we do know that it can't be
    // deeper than 8 nodes
    let mut refs: [Option<&'static ADTNode>; ADT_MAX_DEPTH] = [None; ADT_MAX_DEPTH];

    match ADTNode::from_path_trace(strpath, Some(&mut refs)) {
        Ok(n) => {
            // The C callers provide eight-entry arrays and adt_get_reg
            // requires a terminating zero.  Eight nonzero components would
            // consume every slot and cannot be represented as a terminated
            // path, so reject the result before writing any offsets.
            if refs.iter().all(Option::is_some) {
                return AdtError::BadPath as c_int;
            }
            if !offsets.is_null() {
                for (i, &r) in refs.iter().enumerate() {
                    unsafe {
                        let val = r
                            .map(|r| {
                                adt_offset_to_c(r.as_ptr()).unwrap_or(AdtError::BadOffset as c_int)
                            })
                            .unwrap_or_default();
                        *offsets.add(i) = val;
                        if val == 0 {
                            break;
                        }
                    }
                }
            }
            adt_offset_to_c(n.as_ptr()).unwrap_or(AdtError::BadOffset as c_int)
        }
        Err(e) => e as c_int,
    }
}

#[no_mangle]
pub unsafe extern "C" fn adt_path_offset(_dt: *const c_void, path: *const c_char) -> c_int {
    let strpath: &str = unsafe { CStr::from_ptr(path).to_str().unwrap() };

    match ADTNode::from_path(strpath) {
        Ok(n) => adt_offset_to_c(n.as_ptr()).unwrap_or(AdtError::BadOffset as c_int),
        Err(e) => e as c_int,
    }
}

#[no_mangle]
pub unsafe extern "C" fn adt_get_reg(
    _dt: *const c_void,
    offsets: *mut i32,
    prop: *const c_char,
    i: c_int,
    paddr: *mut u64,
    psize: *mut u64,
) -> c_int {
    let strname: &str = unsafe { CStr::from_ptr(prop).to_str().unwrap() };
    let mut n_offs: usize = 0;
    let mut refs: [Option<&'static ADTNode>; ADT_MAX_DEPTH] = [None; ADT_MAX_DEPTH];

    unsafe {
        // Unlike adt_path_offset_trace(), we need to know
        // the exact number of nodes in the path.
        if offsets.is_null() || *offsets == 0 {
            return AdtError::BadOffset as c_int;
        }

        while n_offs < ADT_MAX_DEPTH && *offsets.add(n_offs) != 0 {
            n_offs += 1;
        }
        // A path without a sentinel is not a valid bounded path.  This also
        // keeps the eight-entry refs array from being indexed out of bounds.
        if n_offs == ADT_MAX_DEPTH {
            return AdtError::BadPath as c_int;
        }
        for j in 0..n_offs {
            let offset = *offsets.add(j);
            refs[j] = match node_from_c_offset(offset) {
                Ok(node) => Some(node),
                Err(e) => return e as c_int,
            };
        }
    }

    match get_reg_container(&refs, strname, i) {
        Ok((a, s)) => {
            if !paddr.is_null() {
                unsafe {
                    *paddr = a;
                }
            }

            if !psize.is_null() {
                unsafe {
                    *psize = s;
                }
            }

            return 0;
        }
        Err(e) => {
            return e as c_int;
        }
    }
}
