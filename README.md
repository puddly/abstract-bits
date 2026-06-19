Turn combinations of bit and byte fields into a structs, even if they represent
Options and Lists.

# Difference to bit-field crates
Let's jump directly into an example. You want to map a zigbee *Link Status
Command* to a high level rust struct. The frame's shape changes depending 
on some bits. 

This is the spec for the frame:
```txt
Bit: |  0 – 4      |      5      |    6       |    7     |       8 -
     | List length | First frame | Last frame | Reserved | Link status list
```

Each `link status` is:
```txt
Bit: |         0 – 15           |    16-18      |     19   |    20-22      |   23
     | Neighbor network address | Incoming cost | Reserved | Outgoing cost | Reserved
```

Its especially tricky that an earlier *bitfield* is determining the list length. Not even a hacky combination of `serde` and a `bitfield` crate can generate (de)-serialize code for us. 

Which is why we now have `abstract-bits`!
```rust
use abstract_bits::{abstract_bits, AbstractBits};

#[abstract_bits]
struct LinkStatusCommand {
    link_statuses_len: u5,
    is_first_frame: bool,
    is_last_frame: bool,
    reserved: u1,
    #[abstract_bits(length_from = link_statuses_len)]
    link_statuses: Vec<LinkStatus>,
}

#[abstract_bits]
struct LinkStatus {
    neighbor_address: u16,
    incoming_cost: u3,
    reserved: u1,
    outgoing_cost: u3,
    reserved: u1,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = LinkStatusCommand {
        is_first_frame: false,
        is_last_frame: true,
        link_statuses: Vec::new(),
    }.to_abstract_bytes()?;
    let link_status_cmd = LinkStatusCommand::from_abstract_bytes(&bytes)?;
    print!("number of links: {}", link_status_cmd.link_statuses.len());
    Ok(())
}
```

# Usage
## With a struct
- Add `#[abstract-bits]` above your struct and any *derives*.
- Use `u<n>` (`n` a natural number larger than zero) for numeric fields. In the
  transformed struct these will transform to the smallest rust primitives that
  can represent them. For example an `u7` will become an `u8`.
- Add padding (if needed) in between fields using `reserved = u<n>`.
- For each `Option` field add `#[abstract_bits(presence_from = <controller_field>)]`
  above the field, where `<controller_field>` is a `bool` field that controls
  whether the `Option` is `Some` or `None`.
- For each `Vec` field add `#[abstract_bits(length_from = <controller_field>)]`
  above the field, where `<controller_field>` is a numeric field that controls
  the length of the `Vec`.
- For a `Vec` field that should be read until the input (or the enclosing TLV
  value) is exhausted rather than from a length prefix, use
  `#[abstract_bits(rest(max_bits = <N>))]`. `<N>` bounds the serialized size in
  bits, which such an otherwise-unbounded field needs.

## With an enum
- Add `#[abstract-bits(bits = <N>)]` above your enum. Replace `N` with the
  number of bits the enum should occupy when serialized. Make sure any *derives*
  follow after.
- Explicitly assign every variant a value.
- Add a `#[repr(<Type>]` attribute, for example `#[repr(u8)]`.

## With a TLV enum
TLV structures (`tag | length | value`) map to a fully typed enum:
- Add `#[abstract_bits(tlv, length = <flavor>)]` and a `#[repr(u8)]` above the
  enum. The `length` flavor is required and describes what the on-wire length field
  measures: `value` (the value's size), `value_minus_one` (Zigbee R23, so the
  value is `length + 1` bytes), or `total` (the whole TLV including the tag and
  length header).
- Give each known variant `#[abstract_bits(tag = <N>)]` and a single field holding
  a payload type that implements `AbstractBits`. The value is decoded from a
  reader bounded to the TLV's length, so trailing bytes added by newer senders
  are ignored rather than misparsed.
- Add one `#[abstract_bits(unknown)]` variant with two named fields — the tag and
  a `Vec<u8>` of the raw value — as the fallback for unrecognized tags.
- An encapsulation TLV (whose value is itself a list of TLVs) is just a payload
  holding a `rest` `Vec` of the enum; recursion needs no extra annotations.

# Complex example
```rust
use abstract_bits::{abstract_bits, AbstractBits, BitReader};

// The size of this is: 
// - 4+1+5+2+2|0+n*18, with n in range 0..u5::MAX 
// so this is at most 14 + 31*18  = 572 bits long
#[abstract_bits]
#[derive(Debug, PartialEq, Eq)] // note: derives follow after
struct Frame {
    header: u4,
    has_source: bool,
    data_len: u5,
    frame_type: Type,
    #[abstract_bits(presence_from = has_source)]
    source: Option<u16>,
    #[abstract_bits(length_from = data_len)]
    data: Vec<Message>,
    #[abstract_bits(rest(max_bits = 512))]
    trailing_data: Vec<u8>,
}

/// This is: 4+3+1+12 = 20 bits long
#[abstract_bits]
#[derive(Debug, PartialEq, Eq)]
struct Message {
    header: u4,
    reserved: u3,
    is_important: bool,
    bits: [bool; 12]
}

#[abstract_bits(bits = 2)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
enum Type {
    #[default]
    System = 0,
    Personal = 1,
    Group = 2,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = Frame {
        header: 12,
        frame_type: Type::default(),
        source: Some(4243),
        data: vec![
            Message {
                header: 9,
                is_important: false,
                bits: [1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1].map(|b| b == 1)
            },
            Message {
                header: 6,
                is_important: false,
                bits: [0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0].map(|b| b == 1)
            },
        ],
        trailing_data: vec![1, 2, 3, 4, 5],
    }.to_abstract_bytes()?;
    let mut reader = BitReader::from(bytes.as_slice());
    let mut frame = Frame::read_abstract_bits(&mut reader)?;
    if frame.frame_type == Type::default() {
        for message in &mut frame.data {
            message.is_important = true;
        }
    }
    let bytes = frame.to_abstract_bytes();
    Ok(())
}
```

# TLV example
A recursive Zigbee R23 TLV block: an encapsulation TLV (tag 72) wrapping a typed
*Fragmentation Parameters* TLV (tag 71), followed by a TLV whose tag we do not
model and therefore keep verbatim.
```rust
use abstract_bits::{abstract_bits, AbstractBits};

#[abstract_bits(tlv, length = value_minus_one)] // R23: value is `length + 1` bytes
#[derive(Debug, PartialEq)]
#[repr(u8)]
enum Tlv {
    #[abstract_bits(tag = 71)]
    Fragmentation(FragmentationParameters),
    #[abstract_bits(tag = 72)]
    Encapsulation(TlvList), // an encapsulation TLV nests more TLVs
    #[abstract_bits(unknown)]
    Unknown { tag: u8, data: Vec<u8> },
}

#[abstract_bits]
#[derive(Debug, PartialEq, Eq)]
struct FragmentationParameters {
    node_id: u16,
    fragmentation_options: u8,
    max_incoming_transfer_unit: u16,
}

// `rest` reads TLVs until the (sub-)reader is exhausted; `max_bits` bounds the
// serialized size so the recursive type has a finite size.
#[abstract_bits]
#[derive(Debug, PartialEq)]
struct TlvList {
    #[abstract_bits(rest(max_bits = 2048))]
    tlvs: Vec<Tlv>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let block = TlvList {
        tlvs: vec![
            Tlv::Encapsulation(TlvList {
                tlvs: vec![Tlv::Fragmentation(FragmentationParameters {
                    node_id: 0x0000,
                    fragmentation_options: 0x01,
                    max_incoming_transfer_unit: 0x0080,
                })],
            }),
            Tlv::Unknown { tag: 0xfe, data: vec![0xde, 0xad] },
        ],
    };

    let bytes = block.to_abstract_bytes()?;
    assert_eq!(TlvList::from_abstract_bytes(&bytes)?, block);
    Ok(())
}
```

# Planned features
- `no-alloc` support
- Support algebraic data-types other than Option (already supported)

# Possible features
- `HashMap`/`HashSet`/`BtreeMap` support

# Acknowledgements
This crate was inspired by [`bilge`](https://crates.io/crates/bilge) and
[`serde`](https://crates.io/crates/serde).
