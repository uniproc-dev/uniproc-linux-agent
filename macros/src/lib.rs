use proc_macro::TokenStream;
use quote::quote;
use syn::{ItemFn, parse_macro_input};

#[proc_macro_attribute]
pub fn unsafe_body(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let mut input = parse_macro_input!(item as ItemFn);

    let body = &input.block;

    let new_block = quote! {
        {
            unsafe {
                #body
            }
        }
    };

    input.block = syn::parse2(new_block).expect("Failed to parse new block");

    TokenStream::from(quote! {
        #input
    })
}
