fn main() {
    // English strings live in the .slint sources; translations are bundled
    // from translations/<lang>/LC_MESSAGES/vykey-desktop.po. No default context:
    // the same English text gets one translation wherever it appears (use
    // `@tr("context" => "text")` where a language needs to tell them apart).
    let config = slint_build::CompilerConfiguration::new()
        .with_bundled_translations("translations")
        .with_default_translation_context(slint_build::DefaultTranslationContext::None);
    slint_build::compile_with_config("ui/app.slint", config).expect("failed to compile Slint UI");
}
