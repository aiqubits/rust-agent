use std::sync::Arc;

use rust_agent_prompt::{
    AssembledPrompt, PromptAssembly, PromptAssemblyBinding, PromptAssemblyRequest, PromptContext,
    PromptError, PromptFuture,
};

struct Assembly;

impl PromptAssembly for Assembly {
    fn assemble(
        &self,
        _context: PromptContext,
        request: PromptAssemblyRequest,
    ) -> PromptFuture<'_, Result<AssembledPrompt, PromptError>> {
        Box::pin(async move { Ok(request.builder().finish()) })
    }
}

fn main() {
    let binding = PromptAssemblyBinding::from_provider(Arc::new(Assembly));
    let _provider = binding.provider;
}
