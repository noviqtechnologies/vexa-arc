pub mod adapter;
pub mod claude_code;
pub mod cursor;
pub mod mcp_jsonrpc;

pub use adapter::{AdapterError, HostAdapter, HostResponse};
pub use claude_code::ClaudeCodeAdapter;
pub use cursor::CursorAdapter;
pub use mcp_jsonrpc::McpJsonRpcInterceptor;
