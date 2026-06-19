use proc_macro2::{Literal, TokenStream};
use quote::quote;
use syn::Ident;

use crate::codegen::generics_to_fully_qualified;
use crate::model::{TlvVariant, TlvVariantKind};

pub fn read(
    variants: &[TlvVariant],
    repr: &Ident,
    enum_name: &Literal,
    offset: isize,
) -> TokenStream {
    let mut tagged_arms = Vec::new();
    let mut unknown_arm = None;
    for variant in variants {
        match &variant.kind {
            TlvVariantKind::Tagged {
                ident,
                tag,
                payload,
            } => {
                let tag_lit = Literal::usize_unsuffixed(*tag);
                let payload = generics_to_fully_qualified(payload.clone());
                tagged_arms.push(quote! {
                    #tag_lit => Self::#ident(
                        <#payload as ::abstract_bits::AbstractBits>::read_abstract_bits(
                            &mut value,
                        )
                        .map_err(|cause| cause.read_tlv(#enum_name, Some(tag as usize)))?
                    ),
                });
            }
            TlvVariantKind::Unknown {
                ident,
                tag_field,
                data_field,
            } => {
                unknown_arm = Some(quote! {
                    other => Self::#ident {
                        #tag_field: other,
                        #data_field: value.remaining_bytes(),
                    },
                });
            }
        }
    }

    quote! {
        let tag = <#repr as ::abstract_bits::AbstractBits>::read_abstract_bits(reader)
            .map_err(|cause| cause.read_tlv(#enum_name, None))?;
        let length = u8::read_abstract_bits(reader)
            .map_err(|cause| cause.read_tlv(#enum_name, Some(tag as usize)))?;

        // The value size is the length field plus the dialect's offset
        let value_bits = (length as isize + #offset) as usize * 8;
        let mut value = reader.split_off(value_bits).map_err(|cause| {
            ::abstract_bits::FromBytesError::ReadTlv {
                tag: Some(tag as usize),
                enum_name: #enum_name,
                cause: ::abstract_bits::ReadErrorCause::NotEnoughInput {
                    ty: #enum_name,
                    cause,
                },
            }
        })?;

        Ok(match tag {
            #(#tagged_arms)*
            #unknown_arm
        })
    }
}

pub fn write(variants: &[TlvVariant], repr: &Ident, offset: isize) -> TokenStream {
    let mut arms = Vec::new();
    for variant in variants {
        match &variant.kind {
            TlvVariantKind::Tagged { ident, tag, .. } => {
                let tag_lit = Literal::usize_unsuffixed(*tag);

                arms.push(quote! {
                    Self::#ident(payload) => {
                        ::abstract_bits::AbstractBits::write_abstract_bits(
                            &(#tag_lit as #repr), writer,
                        )?;
                        let length_pos = writer.bits_written();
                        writer.skip(8).map_err(|cause|
                            ::abstract_bits::ToBytesError::BufferTooSmall {
                                ty: ::core::any::type_name::<Self>(),
                                cause,
                            })?;
                        let value_start = writer.bits_written();
                        ::abstract_bits::AbstractBits::write_abstract_bits(payload, writer)?;
                        let value_bytes = (writer.bits_written() - value_start) / 8;
                        let length = (value_bytes as isize - #offset) as u8;
                        writer.write_u8_at(length_pos, length).map_err(|cause|
                            ::abstract_bits::ToBytesError::BufferTooSmall {
                                ty: ::core::any::type_name::<Self>(),
                                cause,
                            })?;
                    }
                });
            }
            TlvVariantKind::Unknown {
                ident,
                tag_field,
                data_field,
            } => {
                arms.push(quote! {
                    Self::#ident { #tag_field, #data_field } => {
                        ::abstract_bits::AbstractBits::write_abstract_bits(#tag_field, writer)?;
                        let length = (#data_field.len() as isize - #offset) as u8;
                        ::abstract_bits::AbstractBits::write_abstract_bits(&length, writer)?;

                        for byte in #data_field.iter() {
                            ::abstract_bits::AbstractBits::write_abstract_bits(byte, writer)?;
                        }
                    }
                });
            }
        }
    }

    quote! {
        match self {
            #(#arms)*
        }
        Ok(())
    }
}
