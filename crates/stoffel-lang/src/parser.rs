use crate::ast::{AstNode, FieldDefinition, Parameter, Pragma, Value};
use crate::errors::{CompilerError, CompilerResult, SourceLocation};
use std::iter::Peekable;
use std::mem;
use std::slice::Iter;

use crate::lexer::{TokenInfo, TokenKind};

struct Parser<'a> {
    tokens: Peekable<Iter<'a, TokenInfo>>,
    current_token_info: Option<&'a TokenInfo>, // Store the current token info
    last_location: SourceLocation,
    node_id_counter: usize, // Counter for assigning unique node IDs
    recover: bool,
    errors: Vec<CompilerError>,
}

impl<'a> Parser<'a> {
    fn new(tokens: &'a [TokenInfo], filename: &str, recover: bool) -> Self {
        let mut iter = tokens.iter().peekable();
        let current = iter.next();
        Parser {
            tokens: iter,
            current_token_info: current,
            last_location: SourceLocation {
                file: filename.to_string(),
                line: 1,
                column: 1,
            },
            node_id_counter: 0, // Initialize counter
            recover,
            errors: Vec::new(),
        }
    }

    // Consumes the current token and advances to the next one.
    // Returns the *consumed* token's info.
    fn advance(&mut self) -> Option<&'a TokenInfo> {
        let consumed = self.current_token_info;
        if let Some(info) = consumed {
            self.last_location = info.location.clone(); // Update last location
        }
        self.current_token_info = self.tokens.next();
        consumed
    }

    // Checks if the current token matches the expected kind.
    fn check(&self, kind: &TokenKind) -> bool {
        match self.current_token_info {
            Some(info) => mem::discriminant(&info.kind) == mem::discriminant(kind),
            None => matches!(kind, TokenKind::Eof),
        }
    }

    // Checks if the next token matches the expected kind without consuming it.
    fn check_next(&mut self, kind: &TokenKind) -> bool {
        self.tokens
            .peek()
            .is_some_and(|info| mem::discriminant(&info.kind) == mem::discriminant(kind))
    }

    // Checks if the current token is a specific keyword.
    fn check_keyword(&self, keyword: &str) -> bool {
        matches!(self.current_token_info, Some(TokenInfo { kind: TokenKind::Keyword(k), .. }) if k == keyword)
    }

    // --- Core token consumption helpers ---
    // Consumes the current token if it matches the expected kind, otherwise returns an error.
    fn consume(
        &mut self,
        expected: &TokenKind,
        error_message: &str,
    ) -> CompilerResult<&'a TokenInfo> {
        if self.check(expected) {
            Ok(self.advance().unwrap()) // Safe unwrap because check succeeded
        } else {
            let expected_str = match expected {
                TokenKind::Identifier(_) => "identifier".to_string(),
                TokenKind::Keyword(k) => format!("keyword '{}'", k),
                TokenKind::Operator(op) => format!("operator '{}'", op),
                _ => format!("{:?}", expected),
            };

            let (found_str, location) = match self.current_token_info {
                Some(token) => (format!("{:?}", token), token.location.clone()),
                None => ("end of file".to_string(), self.last_location.clone()),
            };

            Err(CompilerError::syntax_error(
                format!(
                    "{} Expected {}, found {}",
                    error_message, expected_str, found_str
                ),
                location,
            )
            .with_hint(format!("Try adding {} here", expected_str)))
        }
    }

    // Consumes the current token if it's a specific keyword, otherwise returns an error.
    fn consume_keyword(
        &mut self,
        keyword: &str,
        error_message: &str,
    ) -> CompilerResult<&'a TokenInfo> {
        if self.check_keyword(keyword) {
            Ok(self.advance().unwrap()) // Safe unwrap because check succeeded
        } else {
            let (found_str, location) = match self.current_token_info {
                Some(token) => (format!("{:?}", token), token.location.clone()),
                None => ("end of file".to_string(), self.last_location.clone()),
            };

            Err(CompilerError::syntax_error(
                format!(
                    "{} Expected keyword '{}', found {}",
                    error_message, keyword, found_str
                ),
                location,
            )
            .with_hint(format!("Try using the '{}' keyword here", keyword)))
        }
    }

    // Helper to get the next unique node ID
    fn next_node_id(&mut self) -> usize {
        let id = self.node_id_counter;
        self.node_id_counter += 1;
        id
    }

    fn pragmas_include_builtin(pragmas: &[Pragma]) -> bool {
        pragmas.iter().any(|pragma| match pragma {
            Pragma::Simple(name, _) | Pragma::KeyValue(name, _, _) => name == "builtin",
        })
    }

    fn report_recoverable_error(&mut self, error: CompilerError) -> CompilerResult<()> {
        if self.recover {
            self.errors.push(error);
            Ok(())
        } else {
            Err(error)
        }
    }

    fn is_statement_start(&self) -> bool {
        match self.current_token_info {
            Some(TokenInfo {
                kind: TokenKind::Keyword(keyword),
                ..
            }) => matches!(
                keyword.as_str(),
                "var"
                    | "def"
                    | "main"
                    | "builtin"
                    | "type"
                    | "object"
                    | "enum"
                    | "secret"
                    | "if"
                    | "while"
                    | "for"
                    | "return"
                    | "discard"
                    | "import"
                    | "else"
                    | "elif"
            ),
            Some(TokenInfo {
                kind:
                    TokenKind::Identifier(_)
                    | TokenKind::IntLiteral { .. }
                    | TokenKind::FloatLiteral(_)
                    | TokenKind::StringLiteral(_)
                    | TokenKind::BoolLiteral(_)
                    | TokenKind::NilLiteral
                    | TokenKind::LParen
                    | TokenKind::LBracket
                    | TokenKind::LBrace,
                ..
            }) => true,
            _ => false,
        }
    }

    fn synchronize_after_error(&mut self, error_location: &SourceLocation) {
        if self
            .current_token_info
            .is_some_and(|token| token.location == *error_location)
        {
            self.advance();
        }

        while self.check(&TokenKind::Newline) {
            self.advance();
        }

        if self.check(&TokenKind::Dedent)
            || self.check(&TokenKind::Eof)
            || self.is_statement_start()
        {
            return;
        }

        while !self.check(&TokenKind::Newline)
            && !self.check(&TokenKind::Dedent)
            && !self.check(&TokenKind::Eof)
        {
            self.advance();
        }

        while self.check(&TokenKind::Newline) {
            self.advance();
        }
    }

    // Helper to parse an indented block of statements
    fn gensym(&mut self, base: &str) -> String {
        self.node_id_counter += 1;
        format!("__{}_{}", base, self.node_id_counter)
    }

    /// Desugars f"a {x} b" into "a " + to_string(x) + " b".
    /// Interpolations are restricted to identifiers and dotted field chains.
    fn desugar_fstring(&mut self, text: &str, location: SourceLocation) -> CompilerResult<AstNode> {
        let string_part = |s: &str, location: &SourceLocation| AstNode::Literal {
            value: Value::String(s.to_string()),
            location: location.clone(),
        };

        let mut parts: Vec<AstNode> = Vec::new();
        let mut literal = String::new();
        let mut chars = text.chars().peekable();
        while let Some(c) = chars.next() {
            match c {
                '{' if chars.peek() == Some(&'{') => {
                    chars.next();
                    literal.push('{');
                }
                '}' if chars.peek() == Some(&'}') => {
                    chars.next();
                    literal.push('}');
                }
                '{' => {
                    let mut expr = String::new();
                    let mut closed = false;
                    for c in chars.by_ref() {
                        if c == '}' {
                            closed = true;
                            break;
                        }
                        expr.push(c);
                    }
                    if !closed {
                        return Err(CompilerError::syntax_error(
                            "Unclosed '{' in f-string",
                            location,
                        ));
                    }
                    let expr = expr.trim();
                    let valid = !expr.is_empty()
                        && expr.split('.').all(|segment| {
                            let mut chars = segment.chars();
                            chars
                                .next()
                                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                                && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
                        });
                    if !valid {
                        return Err(CompilerError::syntax_error(
                            format!(
                                "f-string interpolation '{{{}}}' must be a variable or dotted field access",
                                expr
                            ),
                            location,
                        )
                        .with_hint("Bind complex expressions to a variable first"));
                    }
                    if !literal.is_empty() {
                        parts.push(string_part(&literal, &location));
                        literal.clear();
                    }
                    let mut segments = expr.split('.');
                    let mut node =
                        AstNode::Identifier(segments.next().unwrap().to_string(), location.clone());
                    for field in segments {
                        node = AstNode::FieldAccess {
                            object: Box::new(node),
                            field_name: field.to_string(),
                            location: location.clone(),
                        };
                    }
                    parts.push(AstNode::FunctionCall {
                        function: Box::new(AstNode::Identifier(
                            "to_string".to_string(),
                            location.clone(),
                        )),
                        arguments: vec![node],
                        location: location.clone(),
                        resolved_return_type: None,
                    });
                }
                '}' => {
                    return Err(CompilerError::syntax_error(
                        "Single '}' in f-string; use '}}' for a literal brace",
                        location,
                    ));
                }
                c => literal.push(c),
            }
        }
        if !literal.is_empty() || parts.is_empty() {
            parts.push(string_part(&literal, &location));
        }

        let mut iter = parts.into_iter();
        let mut result = iter.next().expect("at least one part");
        for part in iter {
            result = AstNode::BinaryOperation {
                op: "+".to_string(),
                left: Box::new(result),
                right: Box::new(part),
                location: location.clone(),
            };
        }
        // Anchor the result as a string even when it starts with an
        // interpolation followed by nothing (to_string already returns one).
        Ok(result)
    }

    /// Parses the tail of `[expr for x in iterable if cond]` (the leading
    /// expression is already parsed) and desugars it to a block that builds
    /// a list with a for-loop.
    fn parse_list_comprehension(
        &mut self,
        element: AstNode,
        location: SourceLocation,
    ) -> CompilerResult<AstNode> {
        self.consume_keyword("for", "Expected 'for' in comprehension")?;
        let var_token = self.consume(
            &TokenKind::Identifier("".to_string()),
            "Expected loop variable in comprehension",
        )?;
        let var_name = match &var_token.kind {
            TokenKind::Identifier(n) => n.clone(),
            _ => unreachable!(),
        };
        self.consume_keyword("in", "Expected 'in' in comprehension")?;
        let iterable = self.parse_expression()?;
        let condition = if self.check_keyword("if") {
            self.advance();
            Some(self.parse_expression()?)
        } else {
            None
        };
        self.consume(&TokenKind::RBracket, "Expected ']' to close comprehension")?;

        let result_name = self.gensym("comprehension");
        let append_call = AstNode::FunctionCall {
            function: Box::new(AstNode::Identifier("append".to_string(), location.clone())),
            arguments: vec![
                AstNode::Identifier(result_name.clone(), location.clone()),
                element,
            ],
            location: location.clone(),
            resolved_return_type: None,
        };
        let body = match condition {
            Some(condition) => AstNode::Block(vec![AstNode::IfExpression {
                condition: Box::new(condition),
                then_branch: Box::new(AstNode::Block(vec![append_call])),
                else_branch: None,
            }]),
            None => AstNode::Block(vec![append_call]),
        };

        Ok(AstNode::Block(vec![
            AstNode::VariableDeclaration {
                name: result_name.clone(),
                value: Some(Box::new(AstNode::ListLiteral {
                    elements: Vec::new(),
                    location: location.clone(),
                })),
                type_annotation: None,
                is_mutable: true,
                is_secret: false,
                location: location.clone(),
            },
            AstNode::ForLoop {
                variables: vec![var_name],
                iterable: Box::new(iterable),
                body: Box::new(body),
                location: location.clone(),
            },
            AstNode::Identifier(result_name, location),
        ]))
    }

    /// Parses `match subject:` with literal `case` arms and desugars it to
    /// an if/elif chain over a bound subject variable.
    fn parse_match_statement(&mut self) -> CompilerResult<AstNode> {
        let location = self.get_location();
        self.advance(); // consume 'match'
        let subject = self.parse_expression()?;
        self.consume(&TokenKind::Colon, "Expected ':' after match subject")?;
        self.consume(
            &TokenKind::Newline,
            "Expected newline after ':' before match cases",
        )?;
        while self.check(&TokenKind::Newline) {
            self.advance();
        }
        self.consume(&TokenKind::Indent, "Expected indented match cases")?;

        let subject_name = self.gensym("match_subject");
        let mut cases: Vec<(Option<AstNode>, AstNode)> = Vec::new();
        while !self.check(&TokenKind::Dedent) && !self.check(&TokenKind::Eof) {
            let case_location = self.get_location();
            match &self.current_token_info {
                Some(TokenInfo {
                    kind: TokenKind::Identifier(id),
                    ..
                }) if id == "case" => {
                    self.advance();
                }
                _ => {
                    return Err(CompilerError::syntax_error(
                        "Expected 'case' in match block",
                        case_location,
                    ));
                }
            }
            let pattern = match &self.current_token_info {
                Some(TokenInfo {
                    kind: TokenKind::Identifier(id),
                    ..
                }) if id == "_" => {
                    self.advance();
                    None
                }
                _ => Some(self.parse_expression()?),
            };
            self.consume(&TokenKind::Colon, "Expected ':' after case pattern")?;
            let body = self.parse_indented_block()?;
            let is_default = pattern.is_none();
            cases.push((pattern, body));
            if is_default && !self.check(&TokenKind::Dedent) && !self.check(&TokenKind::Eof) {
                return Err(CompilerError::syntax_error(
                    "'case _' must be the last case in a match",
                    case_location,
                ));
            }
            while self.check(&TokenKind::Newline) {
                self.advance();
            }
        }
        self.consume(&TokenKind::Dedent, "Expected dedent after match block")?;

        if cases.is_empty() {
            return Err(CompilerError::syntax_error(
                "match must have at least one case",
                location,
            ));
        }

        let mut else_node: Option<Box<AstNode>> = None;
        for (pattern, body) in cases.into_iter().rev() {
            match pattern {
                None => else_node = Some(Box::new(body)),
                Some(pattern) => {
                    let condition = AstNode::BinaryOperation {
                        op: "==".to_string(),
                        left: Box::new(AstNode::Identifier(subject_name.clone(), location.clone())),
                        right: Box::new(pattern),
                        location: location.clone(),
                    };
                    else_node = Some(Box::new(AstNode::IfExpression {
                        condition: Box::new(condition),
                        then_branch: Box::new(body),
                        else_branch: else_node,
                    }));
                }
            }
        }

        Ok(AstNode::Block(vec![
            AstNode::VariableDeclaration {
                name: subject_name,
                value: Some(Box::new(subject)),
                type_annotation: None,
                is_mutable: true,
                is_secret: false,
                location: location.clone(),
            },
            *else_node.expect("at least one case"),
        ]))
    }

    fn parse_indented_block(&mut self) -> CompilerResult<AstNode> {
        // Allow multiple newlines before the indented block starts
        if let Err(error) = self.consume(
            &TokenKind::Newline,
            "Expected newline after ':' before indented block",
        ) {
            if self.recover {
                self.errors.push(error);
                self.synchronize_after_error(&self.last_location.clone());
                return Ok(AstNode::Block(Vec::new()));
            }
            return Err(error);
        }
        while self.check(&TokenKind::Newline) {
            self.advance(); // Skip extra blank lines
        }
        if let Err(error) = self.consume(&TokenKind::Indent, "Expected indentation for block") {
            if self.recover {
                self.errors.push(error);
                self.synchronize_after_error(&self.last_location.clone());
                return Ok(AstNode::Block(Vec::new()));
            }
            return Err(error);
        }

        let mut statements = Vec::new();
        while !self.check(&TokenKind::Dedent) && !self.check(&TokenKind::Eof) {
            match self.parse_statement_or_declaration() {
                Ok(statement) => statements.push(statement),
                Err(error) if self.recover => {
                    let error_location = error.location.clone();
                    self.errors.push(error);
                    self.synchronize_after_error(&error_location);
                    continue;
                }
                Err(error) => return Err(error),
            }
            // Skip optional newlines within the block
            while self.check(&TokenKind::Newline) {
                self.advance();
            }
        }

        self.consume(&TokenKind::Dedent, "Expected dedentation to end block")?;

        Ok(AstNode::Block(statements))
    }

    // --- Parsing Functions ---

    // Parses a full program (sequence of statements/declarations)
    fn parse_program(&mut self) -> CompilerResult<AstNode> {
        // --- Skip leading newlines ---
        while self.check(&TokenKind::Newline) {
            self.advance();
        }
        // ---------------------------
        let mut statements = Vec::new();
        while !self.check(&TokenKind::Eof) && !self.check(&TokenKind::Dedent) {
            // Stop at EOF or Dedent
            match self.parse_statement_or_declaration() {
                Ok(statement) => statements.push(statement),
                Err(error) if self.recover => {
                    let error_location = error.location.clone();
                    self.errors.push(error);
                    self.synchronize_after_error(&error_location);
                    continue;
                }
                Err(error) => return Err(error),
            }
            // Skip optional newlines between statements
            while self.check(&TokenKind::Newline) {
                self.advance();
            }
        }
        // If only one statement, return it directly, otherwise wrap in a block
        if statements.len() == 1 {
            Ok(statements.pop().unwrap())
        } else {
            Ok(AstNode::Block(statements))
        }
    }

    // Parses either a statement or a declaration
    fn parse_statement_or_declaration(&mut self) -> CompilerResult<AstNode> {
        // Look ahead to determine if it's a declaration (let, var, proc, type, etc.)
        match &self.current_token_info {
            Some(TokenInfo {
                kind: TokenKind::Keyword(k),
                ..
            }) => match k.as_str() {
                "var" => self.parse_variable_declaration(),
                "def" => self.parse_function_definition(),
                "main" => Err(CompilerError::syntax_error(
                    "The 'main <name>(...)' entry form is no longer supported",
                    self.get_location(),
                )
                .with_hint("Use 'def main(...)' instead")),
                "builtin" => self.parse_builtin_declaration(),
                "type" if self.check_next(&TokenKind::LParen) => self.parse_expression_statement(),
                "type" | "object" | "enum" => self.parse_type_definition(),
                "secret" => Err(CompilerError::syntax_error(
                    "The 'secret' descriptor is only valid in type annotations",
                    self.get_location(),
                )
                .with_hint("Use forms like 'var x: secret int64', 'param: secret int64', or 'field: secret int64'")),
                "if" => self.parse_if_statement_or_expression(),
                "while" => self.parse_while_loop(),
                "for" => self.parse_for_loop(),
                "return" => self.parse_return_statement(),
                "discard" => self.parse_discard_statement(),
                "import" => self.parse_import_statement(),
                "break" => {
                    self.advance();
                    Ok(AstNode::Break)
                }
                "continue" => {
                    self.advance();
                    Ok(AstNode::Continue)
                }
                "pass" => {
                    self.advance();
                    // `pass` is a no-op; lower it to a Nil literal statement.
                    Ok(AstNode::Literal {
                        value: crate::ast::Value::Nil,
                        location: self.get_location(),
                    })
                }
                _ => self.parse_expression_statement(), // Assume expression if keyword doesn't start a known statement/decl
            },
            // Friendly hard error for legacy 'proc' at start of a declaration
            Some(TokenInfo {
                kind: TokenKind::Identifier(id),
                location,
            }) if id == "proc" => Err(CompilerError::syntax_error(
                "The 'proc' keyword is no longer supported; use 'def'",
                location.clone(),
            )
            .with_hint("Rewrite: def name(args) -> type:")),
            // Special-case legacy 'let' at statement start to give a helpful error
            Some(TokenInfo {
                kind: TokenKind::Identifier(id),
                location,
            }) if id == "let" => Err(CompilerError::syntax_error(
                "The 'let' keyword is no longer supported",
                location.clone(),
            )
            .with_hint("Use 'var' for variable declarations (e.g., 'var x = ...')")),
            // assert <cond>[, <message>] desugars to the builtin assert call.
            Some(TokenInfo {
                kind: TokenKind::Identifier(id),
                location,
            }) if id == "assert" => {
                let location = location.clone();
                self.advance(); // consume 'assert'
                let condition = self.parse_expression()?;
                let mut arguments = vec![condition];
                if self.check(&TokenKind::Comma) {
                    self.advance();
                    arguments.push(self.parse_expression()?);
                }
                Ok(AstNode::FunctionCall {
                    function: Box::new(AstNode::Identifier(
                        "assert".to_string(),
                        location.clone(),
                    )),
                    arguments,
                    location,
                    resolved_return_type: None,
                })
            }
            // match <subject>: case <literal>: ... desugars to an if/elif chain.
            // (Contextual: `match = ...` still assigns to a variable.)
            Some(TokenInfo {
                kind: TokenKind::Identifier(id),
                ..
            }) if id == "match" => {
                if self.check_next(&TokenKind::Assign) {
                    self.parse_expression_statement()
                } else {
                    self.parse_match_statement()
                }
            }
            // Recognizable Python constructs that StoffelLang does not support:
            // give a targeted diagnostic instead of a generic parse error.
            Some(TokenInfo {
                kind: TokenKind::Identifier(id),
                location,
            }) if matches!(
                id.as_str(),
                "try" | "except" | "finally" | "raise" | "with" | "yield"
                    | "lambda" | "del" | "global" | "nonlocal"
            ) =>
            {
                let (message, hint): (String, &str) = match id.as_str() {
                    "try" | "except" | "finally" | "raise" => (
                        format!("'{}' is not supported: StoffelLang has no exception handling", id),
                        "Errors abort execution; validate inputs up front and use return values to signal failure",
                    ),
                    "with" => (
                        "'with' statements are not supported".to_string(),
                        "StoffelLang has no context managers; call functions directly",
                    ),
                    "yield" => (
                        "'yield' is not supported: StoffelLang has no generators".to_string(),
                        "Build and return a list instead",
                    ),
                    "lambda" => (
                        "'lambda' is not supported: StoffelLang has no anonymous functions".to_string(),
                        "Define a named function with 'def' and pass its name to create_closure",
                    ),
                    _ => (
                        format!("'{}' is not supported in StoffelLang", id),
                        "See the language documentation for the supported statement forms",
                    ),
                };
                Err(CompilerError::syntax_error(message, location.clone()).with_hint(hint))
            }
            Some(TokenInfo {
                kind: TokenKind::Identifier(_),
                ..
            }) => self.parse_expression_statement(),
            // Add cases for other statement starters
            _ => {
                let (found_str, location) = match self.current_token_info {
                    Some(token) => (format!("{:?}", token), token.location.clone()),
                    None => ("end of file".to_string(), self.last_location.clone()),
                };

                Err(CompilerError::syntax_error(
                    format!(
                        "Unexpected token at start of statement/declaration: {}",
                        found_str
                    ),
                    location,
                ))
            }
        }
    }

    fn parse_function_definition(&mut self) -> CompilerResult<AstNode> {
        let node_id = self.next_node_id(); // Get a unique ID for this function node
        let start_location = self.get_location(); // Location of 'def'
        self.consume_keyword("def", "Expected 'def'")?; // Consume 'def'
        let name = match self.current_token_info {
            Some(TokenInfo {
                kind: TokenKind::Identifier(n),
                ..
            }) => {
                let name = n.clone();
                self.advance();
                name
            }
            Some(TokenInfo {
                kind: TokenKind::Keyword(k),
                ..
            }) if k == "type" || k == "main" => {
                let name = k.clone();
                self.advance();
                name
            }
            _ => {
                return Err(CompilerError::syntax_error(
                    "Expected function name",
                    self.get_location(),
                ));
            }
        };

        let mut type_params = Vec::new();
        if self.check(&TokenKind::LBracket) {
            self.advance(); // consume '['
            if !self.check(&TokenKind::RBracket) {
                loop {
                    let param_name_token = self.consume(
                        &TokenKind::Identifier("".to_string()),
                        "Expected generic type parameter name",
                    )?;
                    let param_name = match param_name_token {
                        TokenInfo {
                            kind: TokenKind::Identifier(n),
                            ..
                        } => n.clone(),
                        _ => unreachable!(),
                    };
                    if !type_params.contains(&param_name) {
                        type_params.push(param_name);
                    }
                    if self.check(&TokenKind::RBracket) {
                        break;
                    }
                    self.consume(&TokenKind::Comma, "Expected ',' between generic parameters")?;
                }
            }
            self.consume(
                &TokenKind::RBracket,
                "Expected ']' after generic parameters",
            )?;
        }

        self.consume(&TokenKind::LParen, "Expected '(' after function name")?;
        let mut parameters = Vec::new();
        if !self.check(&TokenKind::RParen) {
            loop {
                let is_variadic = if self.check(&TokenKind::Operator("*".to_string())) {
                    self.advance();
                    true
                } else {
                    false
                };
                let param_name_token = self.consume(
                    &TokenKind::Identifier("".to_string()),
                    "Expected parameter name",
                )?;
                let param_name = match param_name_token {
                    TokenInfo {
                        kind: TokenKind::Identifier(n),
                        ..
                    } => n.clone(),
                    _ => unreachable!(), // consume ensures it's an identifier
                };

                // Parse optional type annotation
                let param_type_annotation = if self.check(&TokenKind::Colon) {
                    self.advance(); // Consume ':'
                    Some(Box::new(self.parse_type_annotation()?))
                } else {
                    None
                };
                let default_value = if self.check(&TokenKind::Assign) {
                    self.advance();
                    Some(Box::new(self.parse_expression()?))
                } else {
                    None
                };
                parameters.push(Parameter {
                    name: param_name,
                    type_annotation: param_type_annotation,
                    default_value,
                    is_secret: false,
                    is_variadic,
                });

                if self.check(&TokenKind::RParen) {
                    break;
                }
                self.consume(&TokenKind::Comma, "Expected ',' between parameters")?;
            }
        }
        self.consume(&TokenKind::RParen, "Expected ')' after parameters")?;

        // New syntax: optional '-> <type-or-nil>' before pragmas, then ':' to start body/header end
        let mut return_type: Option<Box<AstNode>> = None;
        if self.check(&TokenKind::Arrow) {
            let arrow_location = self
                .current_token_info
                .map(|t| t.location.clone())
                .unwrap_or_default();
            self.advance(); // consume '->'

            // Check for tuple return type syntax: -> (Type1, Type2)
            // This is not supported - return types must be a single type
            if self.check(&TokenKind::LParen) {
                return Err(CompilerError::syntax_error(
                    "Tuple return types are not supported",
                    arrow_location
                ).with_hint("Return a single value. If you need multiple values, consider using a custom type or restructuring your code."));
            }

            // Special-case: allow 'None' to mean no return (void)
            if matches!(
                self.current_token_info,
                Some(TokenInfo {
                    kind: TokenKind::NilLiteral,
                    ..
                })
            ) {
                // Treat as no return type
                self.advance(); // consume 'None'
                return_type = None;
            } else {
                return_type = Some(Box::new(self.parse_type_annotation()?));
            }
        }

        // Parse optional pragmas (AFTER return arrow, BEFORE ':')
        let mut pragmas = Vec::new();
        if self.check(&TokenKind::LPragma) {
            pragmas = self.parse_pragma()?;
        }

        // Expect ':' to end the header line
        self.consume(&TokenKind::Colon, "Expected ':' after function header")?;

        // For builtins, accept no body (empty block)
        let is_builtin = Self::pragmas_include_builtin(&pragmas);
        let body = if is_builtin {
            // Allow just a header line and no body for builtins
            AstNode::Block(vec![])
        } else {
            // Parse function body after newline and indent
            self.parse_indented_block()?
        };

        Ok(AstNode::FunctionDefinition {
            name: Some(name),
            type_params,
            parameters,
            return_type,
            body: Box::new(body),
            is_secret: false,
            pragmas,                  // Store parsed pragmas
            location: start_location, // Use location of 'def' keyword
            node_id,                  // Store the unique ID
        })
    }

    fn parse_type_definition(&mut self) -> CompilerResult<AstNode> {
        let location = self.get_location();
        // Determine if it's object, enum, or type alias
        if self.check_keyword("object") {
            self.advance(); // Consume 'object'
            self.parse_object_definition(location)
        } else if self.check_keyword("enum") {
            self.advance(); // Consume 'enum'
            let name_token =
                self.consume(&TokenKind::Identifier("".to_string()), "Expected enum name")?;
            let name = match &name_token.kind {
                TokenKind::Identifier(n) => n.clone(),
                _ => unreachable!(),
            };
            self.consume(&TokenKind::Colon, "Expected ':' after enum name")?;
            self.consume(
                &TokenKind::Newline,
                "Expected newline after ':' before enum members",
            )?;
            while self.check(&TokenKind::Newline) {
                self.advance();
            }
            self.consume(&TokenKind::Indent, "Expected indented enum members")?;

            let mut members = Vec::new();
            while !self.check(&TokenKind::Dedent) && !self.check(&TokenKind::Eof) {
                let member_token = self.consume(
                    &TokenKind::Identifier("".to_string()),
                    "Expected enum member name",
                )?;
                let member_name = match &member_token.kind {
                    TokenKind::Identifier(n) => n.clone(),
                    _ => unreachable!(),
                };
                let value = if self.check(&TokenKind::Assign) {
                    self.advance();
                    Some(Box::new(self.parse_expression()?))
                } else {
                    None
                };
                members.push(crate::ast::EnumMember {
                    name: member_name,
                    value,
                });
                while self.check(&TokenKind::Newline) {
                    self.advance();
                }
            }
            self.consume(&TokenKind::Dedent, "Expected dedent after enum members")?;

            if members.is_empty() {
                return Err(CompilerError::syntax_error(
                    "Enum must declare at least one member",
                    location,
                ));
            }

            Ok(AstNode::EnumDefinition {
                name,
                members,
                is_secret: false,
                location,
            })
        } else if self.check_keyword("type") {
            self.advance(); // Consume 'type'
            self.parse_type_alias_definition(location)
        } else {
            Err(CompilerError::syntax_error(
                "Expected 'object', 'enum', or 'type' for type definition",
                location,
            ))
        }
    }

    fn parse_type_alias_definition(&mut self, location: SourceLocation) -> CompilerResult<AstNode> {
        let name_token = self.consume(
            &TokenKind::Identifier("".to_string()),
            "Expected type alias name after 'type'",
        )?;
        let name = match name_token {
            TokenInfo {
                kind: TokenKind::Identifier(n),
                ..
            } => n.clone(),
            _ => unreachable!(),
        };

        self.consume(&TokenKind::Assign, "Expected '=' after type alias name")?;
        let target_type = self.parse_type_annotation()?;

        if !self.check(&TokenKind::Newline)
            && !self.check(&TokenKind::Eof)
            && !self.check(&TokenKind::Dedent)
        {
            return Err(CompilerError::syntax_error(
                format!(
                    "Expected newline, EOF, or dedent after type alias, found {:?}",
                    self.current_token_info
                ),
                self.get_location(),
            ));
        }

        Ok(AstNode::TypeAlias {
            name,
            target_type: Box::new(target_type),
            is_secret: false,
            location,
        })
    }

    fn parse_builtin_declaration(&mut self) -> CompilerResult<AstNode> {
        let location = self.get_location();
        self.consume_keyword("builtin", "Expected 'builtin'")?;

        if self.check_keyword("object") {
            self.advance();
            self.parse_builtin_object_definition(location)
        } else if self.check_keyword("type") {
            self.advance();
            self.parse_builtin_type_definition(false, location)
        } else if matches!(self.current_token_info, Some(TokenInfo { kind: TokenKind::Identifier(id), .. }) if id == "opaque")
        {
            self.advance();
            self.parse_builtin_type_definition(true, location)
        } else {
            Err(CompilerError::syntax_error(
                "Expected 'object', 'type', or 'opaque' after 'builtin'",
                self.get_location(),
            ))
        }
    }

    fn parse_builtin_type_definition(
        &mut self,
        is_opaque_object: bool,
        location: SourceLocation,
    ) -> CompilerResult<AstNode> {
        let name = match self.current_token_info {
            Some(TokenInfo {
                kind: TokenKind::Identifier(ref n),
                ..
            }) => {
                let name = n.clone();
                self.advance();
                name
            }
            Some(TokenInfo {
                kind: TokenKind::NilLiteral,
                ..
            }) => {
                self.advance();
                "None".to_string()
            }
            _ => {
                return Err(CompilerError::syntax_error(
                    "Expected builtin type name",
                    self.get_location(),
                ));
            }
        };

        let target_type = if self.check(&TokenKind::Assign) {
            self.advance();
            Some(Box::new(self.parse_type_annotation()?))
        } else {
            None
        };

        if !self.check(&TokenKind::Newline)
            && !self.check(&TokenKind::Eof)
            && !self.check(&TokenKind::Dedent)
        {
            return Err(CompilerError::syntax_error(
                format!(
                    "Expected newline, EOF, or dedent after builtin type definition, found {:?}",
                    self.current_token_info
                ),
                self.get_location(),
            ));
        }

        Ok(AstNode::BuiltinTypeDefinition {
            name,
            target_type,
            is_opaque_object,
            location,
        })
    }

    fn parse_builtin_object_definition(
        &mut self,
        location: SourceLocation,
    ) -> CompilerResult<AstNode> {
        let name_token = self.consume(
            &TokenKind::Identifier("".to_string()),
            "Expected builtin object name after 'object'",
        )?;
        let name = match name_token {
            TokenInfo {
                kind: TokenKind::Identifier(n),
                ..
            } => n.clone(),
            _ => unreachable!(),
        };

        self.consume(
            &TokenKind::Colon,
            "Expected ':' after builtin object header",
        )?;
        let methods = self.parse_builtin_object_methods()?;

        Ok(AstNode::BuiltinObjectDefinition {
            name,
            methods,
            location,
        })
    }

    fn parse_builtin_object_methods(&mut self) -> CompilerResult<Vec<AstNode>> {
        self.consume(
            &TokenKind::Newline,
            "Expected newline after builtin object header",
        )?;
        while self.check(&TokenKind::Newline) {
            self.advance();
        }
        self.consume(
            &TokenKind::Indent,
            "Expected indented method declarations after builtin object header",
        )?;

        let mut methods = Vec::new();
        while !self.check(&TokenKind::Dedent) && !self.check(&TokenKind::Eof) {
            while self.check(&TokenKind::Newline) {
                self.advance();
            }
            if self.check(&TokenKind::Dedent) || self.check(&TokenKind::Eof) {
                break;
            }

            if !self.check_keyword("def") {
                return Err(CompilerError::syntax_error(
                    "Expected builtin object method declaration starting with 'def'",
                    self.get_location(),
                ));
            }

            let method = self.parse_function_definition()?;
            match &method {
                AstNode::FunctionDefinition { pragmas, .. }
                    if Self::pragmas_include_builtin(pragmas) => {}
                AstNode::FunctionDefinition { location, .. } => {
                    return Err(CompilerError::syntax_error(
                        "Builtin object methods must use the {.builtin.} pragma",
                        location.clone(),
                    ));
                }
                _ => unreachable!(),
            }
            methods.push(method);

            if self.check(&TokenKind::Newline) {
                self.advance();
            }
        }

        self.consume(
            &TokenKind::Dedent,
            "Expected dedentation to end builtin object declaration",
        )?;

        if methods.is_empty() {
            return Err(CompilerError::syntax_error(
                "Builtin object definition must have at least one method",
                self.get_location(),
            ));
        }

        Ok(methods)
    }

    /// Parses an object definition.
    /// Syntax:
    ///   object Name:
    ///     field1: Type1
    ///     field2: Type2
    ///
    /// Or with base type:
    ///   object Name(BaseType):
    ///     field1: Type1
    fn parse_object_definition(&mut self, location: SourceLocation) -> CompilerResult<AstNode> {
        // Parse object name
        let name_token = self.consume(
            &TokenKind::Identifier("".to_string()),
            "Expected object name after 'object'",
        )?;
        let name = match name_token {
            TokenInfo {
                kind: TokenKind::Identifier(n),
                ..
            } => n.clone(),
            _ => unreachable!(),
        };

        // Parse optional base type: object Name(BaseType):
        let base_type = if self.check(&TokenKind::LParen) {
            self.advance(); // Consume '('
            let base = self.parse_type_annotation()?;
            self.consume(&TokenKind::RParen, "Expected ')' after base type")?;
            Some(Box::new(base))
        } else {
            None
        };

        // Expect ':' to start the body
        self.consume(&TokenKind::Colon, "Expected ':' after object header")?;

        // Parse the indented block of field definitions
        let fields = self.parse_object_fields()?;

        Ok(AstNode::ObjectDefinition {
            name,
            base_type,
            fields,
            is_secret: false,
            location,
        })
    }

    /// Parses the fields inside an object definition.
    /// Each field is: field_name: Type
    fn parse_object_fields(&mut self) -> CompilerResult<Vec<FieldDefinition>> {
        let mut fields = Vec::new();

        // Consume any newlines before the block
        while self.check(&TokenKind::Newline) {
            self.advance();
        }

        // Expect indent to start the block
        if !self.check(&TokenKind::Indent) {
            return Err(CompilerError::syntax_error(
                "Expected indented block with field definitions after object header",
                self.get_location(),
            ));
        }
        self.advance(); // Consume Indent

        // Parse field definitions until we see Dedent
        loop {
            // Skip any extra newlines
            while self.check(&TokenKind::Newline) {
                self.advance();
            }

            // Check for end of block
            if self.check(&TokenKind::Dedent) || self.check(&TokenKind::Eof) {
                break;
            }

            if self.check_keyword("secret") {
                return Err(CompilerError::syntax_error(
                    "The 'secret' descriptor is only valid in type annotations",
                    self.get_location(),
                )
                .with_hint("Use 'field_name: secret <type>' instead"));
            }

            // Parse field name
            let field_name_token = self.consume(
                &TokenKind::Identifier("".to_string()),
                "Expected field name",
            )?;
            let field_name = match field_name_token {
                TokenInfo {
                    kind: TokenKind::Identifier(n),
                    ..
                } => n.clone(),
                _ => unreachable!(),
            };

            // Expect ':' followed by type annotation
            self.consume(&TokenKind::Colon, "Expected ':' after field name")?;
            let field_type = self.parse_type_annotation()?;

            fields.push(FieldDefinition {
                name: field_name,
                type_annotation: Box::new(field_type),
                is_secret: false,
            });

            // Consume newline after field definition
            if self.check(&TokenKind::Newline) {
                self.advance();
            }
        }

        // Consume the Dedent
        if self.check(&TokenKind::Dedent) {
            self.advance();
        }

        if fields.is_empty() {
            return Err(CompilerError::syntax_error(
                "Object definition must have at least one field",
                self.get_location(),
            ));
        }

        Ok(fields)
    }

    fn parse_if_statement_or_expression(&mut self) -> CompilerResult<AstNode> {
        let _start_location = self.get_location(); // Location of 'if'
        self.consume_keyword("if", "Expected 'if'")?;
        let condition = self.parse_expression()?;
        self.consume(&TokenKind::Colon, "Expected ':' after if condition")?;
        let then_branch = self.parse_indented_block()?;

        let mut elif_clauses = Vec::new();
        while self.check_keyword("elif") {
            self.advance(); // Consume 'elif'
            let elif_condition = self.parse_expression()?;
            self.consume(&TokenKind::Colon, "Expected ':' after elif condition")?;
            let elif_body = self.parse_indented_block()?;
            elif_clauses.push((elif_condition, elif_body));
        }

        let else_branch = if self.check_keyword("else") {
            self.advance(); // Consume 'else'
            self.consume(&TokenKind::Colon, "Expected ':' after else")?;
            Some(Box::new(self.parse_indented_block()?))
        } else {
            None
        };

        // Construct nested IfExpressions from the right: each elif becomes the
        // else-branch of the clause before it, so conditions are evaluated in
        // source order (if first, then elifs top to bottom, else last).
        let mut else_node = else_branch;
        for (elif_condition, elif_body) in elif_clauses.into_iter().rev() {
            else_node = Some(Box::new(AstNode::IfExpression {
                condition: Box::new(elif_condition),
                then_branch: Box::new(elif_body),
                else_branch: else_node,
            }));
        }

        Ok(AstNode::IfExpression {
            condition: Box::new(condition),
            then_branch: Box::new(then_branch),
            else_branch: else_node,
        })
    }

    // TODO: Add location to WhileLoop node
    fn parse_while_loop(&mut self) -> CompilerResult<AstNode> {
        let start_location = self.get_location(); // Location of 'while'
        self.consume_keyword("while", "Expected 'while'")?;
        let condition = self.parse_expression()?;
        self.consume(&TokenKind::Colon, "Expected ':' after while condition")?;
        let body = self.parse_indented_block()?;

        Ok(AstNode::WhileLoop {
            condition: Box::new(condition),
            body: Box::new(body),
            location: start_location, // Use location of 'while'
        })
    }

    fn parse_for_loop(&mut self) -> CompilerResult<AstNode> {
        let start_location = self.get_location(); // Location of 'for'
        self.consume_keyword("for", "Expected 'for'")?;

        // Parse one or more identifiers separated by commas
        let mut variables = Vec::new();
        let first_ident = self.consume(
            &TokenKind::Identifier("".to_string()),
            "Expected loop variable name",
        )?;
        let first_name = match &first_ident.kind {
            TokenKind::Identifier(n) => n.clone(),
            _ => unreachable!(),
        };
        variables.push(first_name);
        while self.check(&TokenKind::Comma) {
            self.advance(); // consume ','
            let ident_tok = self.consume(
                &TokenKind::Identifier("".to_string()),
                "Expected loop variable name after ','",
            )?;
            if let TokenKind::Identifier(n) = &ident_tok.kind {
                variables.push(n.clone());
            }
        }

        // Expect 'in'
        // 'in' is tokenized as a keyword in our lexer
        self.consume_keyword("in", "Expected 'in' in for-loop header")?;

        // Parse iterable expression - supports both range syntax (a..b) and collection iteration
        let iterable = {
            // Parse left expression with precedence just below '..' so we stop before parsing '..'
            let left = self.parse_expression_with_precedence(5)?;

            // Check if next token is '..' for range syntax
            match &self.current_token_info {
                Some(TokenInfo {
                    kind: TokenKind::Operator(op),
                    ..
                }) if op == ".." => {
                    // This is a range expression - consume '..' and parse right side
                    self.advance();
                    let right = self.parse_expression_with_precedence(4)?;
                    AstNode::BinaryOperation {
                        op: "..".to_string(),
                        left: Box::new(left),
                        right: Box::new(right),
                        location: self.last_location.clone(),
                    }
                }
                _ => {
                    // Not a range - this is a collection/iterable expression
                    // The 'left' expression is our iterable (e.g., a list variable)
                    left
                }
            }
        };

        // Expect ':' then a block
        self.consume(&TokenKind::Colon, "Expected ':' after for-loop header")?;
        let body = self.parse_indented_block()?;

        Ok(AstNode::ForLoop {
            variables,
            iterable: Box::new(iterable),
            body: Box::new(body),
            location: start_location,
        })
    }

    fn parse_return_statement(&mut self) -> CompilerResult<AstNode> {
        let start_location = self.get_location();
        self.consume_keyword("return", "Expected 'return'")?;
        let value = if !self.check(&TokenKind::Newline)
            && !self.check(&TokenKind::Eof)
            && !self.check(&TokenKind::Dedent)
        {
            Some(Box::new(self.parse_expression()?))
        } else {
            None
        };

        Ok(AstNode::Return {
            value,
            location: start_location,
        })
    }

    fn parse_discard_statement(&mut self) -> CompilerResult<AstNode> {
        let start_location = self.get_location(); // Location of 'discard'
        self.consume_keyword("discard", "Expected 'discard'")?;
        let expression = self.parse_expression()?;

        // Expect newline, EOF, or Dedent after the statement
        if !self.check(&TokenKind::Newline)
            && !self.check(&TokenKind::Eof)
            && !self.check(&TokenKind::Dedent)
            && !self.check(&TokenKind::RParen)
        /* Allow in expr lists */
        {
            return Err(CompilerError::syntax_error(
                format!(
                    "Expected newline, EOF, or dedent after discard statement, found {:?}",
                    self.current_token_info
                ),
                self.get_location(),
            ));
        }

        Ok(AstNode::DiscardStatement {
            expression: Box::new(expression),
            location: start_location,
        })
    }

    /// Parses an import statement.
    /// Syntax: import module.submodule [as alias]
    /// Syntax: import "../relative/path.stfl" [as alias]
    /// Example: import utils.math
    /// Example: import utils.math as m
    /// Example: import "../shared/main.stfl" as shared
    fn parse_import_statement(&mut self) -> CompilerResult<AstNode> {
        let start_location = self.get_location();
        self.consume_keyword("import", "Expected 'import'")?;

        let (module_path, raw_path) = match self.current_token_info {
            Some(TokenInfo {
                kind: TokenKind::StringLiteral(path),
                ..
            }) => {
                let raw_path = path.clone();
                self.advance();
                let stem = std::path::Path::new(&raw_path)
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .filter(|s| !s.is_empty())
                    .unwrap_or("module")
                    .to_string();
                (vec![stem], Some(raw_path))
            }
            _ => {
                // Parse module path: identifier.identifier.identifier...
                let mut module_path = Vec::new();
                let first_ident = self.consume(
                    &TokenKind::Identifier("".to_string()),
                    "Expected module name or quoted path after 'import'",
                )?;
                module_path.push(match &first_ident.kind {
                    TokenKind::Identifier(n) => n.clone(),
                    _ => unreachable!(),
                });

                // Continue parsing dot-separated identifiers
                while self.check(&TokenKind::Dot) {
                    self.advance(); // consume '.'
                    let next_ident = self.consume(
                        &TokenKind::Identifier("".to_string()),
                        "Expected module name after '.'",
                    )?;
                    module_path.push(match &next_ident.kind {
                        TokenKind::Identifier(n) => n.clone(),
                        _ => unreachable!(),
                    });
                }

                (module_path, None)
            }
        };

        // Optional alias: "as <identifier>"
        let alias = if self.check_keyword("as") {
            self.advance(); // consume 'as'
            let alias_token = self.consume(
                &TokenKind::Identifier("".to_string()),
                "Expected alias name after 'as'",
            )?;
            Some(match &alias_token.kind {
                TokenKind::Identifier(n) => n.clone(),
                _ => unreachable!(),
            })
        } else {
            None
        };

        // Expect newline, EOF, or Dedent after import statement
        if !self.check(&TokenKind::Newline)
            && !self.check(&TokenKind::Eof)
            && !self.check(&TokenKind::Dedent)
        {
            return Err(CompilerError::syntax_error(
                format!(
                    "Expected newline after import statement, found {:?}",
                    self.current_token_info
                ),
                self.get_location(),
            ));
        }

        Ok(AstNode::Import {
            module_path,
            raw_path,
            alias,
            imported_items: None, // For future "from X import Y" syntax
            location: start_location,
        })
    }

    // --- Pratt Parser for Expressions ---

    // Gets the precedence level of the current token (if it's an infix operator).
    fn current_precedence(&self) -> u8 {
        match &self.current_token_info {
            Some(TokenInfo {
                kind: TokenKind::Operator(op),
                ..
            }) => match op.as_str() {
                "or" | "xor" => 1,
                "and" => 2,
                "==" | "!=" | "<" | "<=" | ">" | ">=" | "is" | "in" => 3, // Comparison operators
                ".." => 4,                                                // Range operator
                "+" | "-" => 5,                                           // Addition/Subtraction
                "*" | "/" | "%" | "mod" => 6, // Multiplication/Division/Remainder/Modulo
                "shl" | "shr" => 6,           // Bit shifts (Nim-style keywords)
                // Add other operators like power (**), bitwise (&, |, ^), etc.
                _ => 0, // Not an infix operator or lowest precedence
            },
            // 'in' is lexed as a keyword but acts as a comparison operator
            Some(TokenInfo {
                kind: TokenKind::Keyword(kw),
                ..
            }) if kw == "in" => 3,
            // Function call '(' has high precedence
            Some(TokenInfo {
                kind: TokenKind::LParen,
                ..
            }) => 7, // Higher than multiplication/division
            // Index access '[' has same precedence as field access
            Some(TokenInfo {
                kind: TokenKind::LBracket,
                ..
            }) => 8, // Same as field access
            // Field access '.' has even higher precedence
            Some(TokenInfo {
                kind: TokenKind::Dot,
                ..
            }) => 8, // Higher than function calls
            _ => 0, // Not an operator
        }
    }

    // Parses a prefix expression (like literals, identifiers, unary operators).
    fn parse_prefix(&mut self) -> CompilerResult<AstNode> {
        let token_info = self.advance().ok_or_else(|| {
            // Use last_location if current is None
            CompilerError::syntax_error(
                "Unexpected end of file while parsing expression",
                self.last_location.clone(),
            )
        })?;

        match &token_info.kind {
            TokenKind::IntLiteral { value, kind, .. } => Ok(AstNode::Literal {
                value: Value::Int {
                    value: *value,
                    kind: kind.clone(),
                },
                location: token_info.location.clone(),
            }),
            TokenKind::FloatLiteral(f) => Ok(AstNode::Literal {
                value: Value::Float(*f),
                location: token_info.location.clone(),
            }),
            TokenKind::StringLiteral(s) => Ok(AstNode::Literal {
                value: Value::String(s.clone()),
                location: token_info.location.clone(),
            }),
            TokenKind::BoolLiteral(b) => Ok(AstNode::Literal {
                value: Value::Bool(*b),
                location: token_info.location.clone(),
            }),
            TokenKind::NilLiteral => Ok(AstNode::Literal {
                value: Value::Nil,
                location: token_info.location.clone(),
            }),
            TokenKind::Identifier(name) if name == "lambda" => Err(CompilerError::syntax_error(
                "'lambda' is not supported: StoffelLang has no anonymous functions",
                token_info.location.clone(),
            )
            .with_hint("Define a named function with 'def' and pass its name to create_closure")),
            TokenKind::Identifier(name)
                if matches!(name.as_str(), "f" | "F")
                    && matches!(
                        self.current_token_info,
                        Some(TokenInfo {
                            kind: TokenKind::StringLiteral(_),
                            ..
                        })
                    ) =>
            {
                let location = token_info.location.clone();
                let Some(TokenInfo {
                    kind: TokenKind::StringLiteral(text),
                    ..
                }) = self.advance()
                else {
                    unreachable!("guard checked the string literal");
                };
                let text = text.clone();
                self.desugar_fstring(&text, location)
            }
            TokenKind::Identifier(name) => Ok(AstNode::Identifier(name.clone(), token_info.location.clone())),
            TokenKind::Keyword(name) if name == "type" => Ok(AstNode::Identifier(name.clone(), token_info.location.clone())),
            TokenKind::LParen => {
                let expr = self.parse_expression_with_precedence(0)?; // Parse expression inside parentheses
                self.consume(&TokenKind::RParen, "Expected ')' after parenthesized expression")?;
                Ok(expr)
            }
            TokenKind::LBracket => {
                // List literal: [elem1, elem2, ...], empty list [], or a
                // comprehension [expr for x in iterable if cond].
                let mut elements = Vec::new();
                if !self.check(&TokenKind::RBracket) {
                    loop {
                        let element = self.parse_expression()?;
                        if elements.is_empty() && self.check_keyword("for") {
                            return self.parse_list_comprehension(
                                element,
                                token_info.location.clone(),
                            );
                        }
                        elements.push(element);
                        if self.check(&TokenKind::RBracket) {
                            break;
                        }
                        self.consume(&TokenKind::Comma, "Expected ',' or ']' after list element")?;
                    }
                }
                self.consume(&TokenKind::RBracket, "Expected ']' after list elements")?;

                // Empty list literals [] are now supported
                // Type will be inferred from context or explicit annotation
                Ok(AstNode::ListLiteral {
                    elements,
                    location: token_info.location.clone(),
                })
            }
            TokenKind::LBrace => {
                // Dict literal: {key1: val1, key2: val2, ...}
                let mut pairs = Vec::new();
                if !self.check(&TokenKind::RBrace) {
                    loop {
                        let key = self.parse_expression()?;
                        self.consume(&TokenKind::Colon, "Expected ':' between dict key and value")?;
                        let value = self.parse_expression()?;
                        pairs.push((key, value));
                        if self.check(&TokenKind::RBrace) {
                            break;
                        }
                        self.consume(&TokenKind::Comma, "Expected ',' or '}' after dict entry")?;
                    }
                }
                self.consume(&TokenKind::RBrace, "Expected '}' after dict entries")?;
                Ok(AstNode::DictLiteral {
                    pairs,
                    location: token_info.location.clone(),
                })
            }
            TokenKind::Operator(op) => {
                // Handle prefix operators (e.g., '-', 'not')
                match op.as_str() {
                    "-" | "not" => {
                        // Define prefix precedence (usually higher than most infix)
                        let prefix_precedence = 6; // Example precedence for unary minus/not
                        let operand = self.parse_expression_with_precedence(prefix_precedence)?;
                        Ok(AstNode::UnaryOperation {
                            op: op.clone(),
                            operand: Box::new(operand),
                            location: token_info.location.clone(),
                        })
                    }
                    _ => Err(CompilerError::syntax_error(format!("Unexpected prefix operator: {}", op), token_info.location.clone())),
                }
            }
            // TODO: Add function calls, list literals, etc.
            _ => Err(CompilerError::syntax_error(format!("Expected expression, found {:?}", token_info.kind), token_info.location.clone())
                    .with_hint("An expression can be a literal, identifier, function call, or use operators like +, -, *, /")),
        }
    }

    // Parses an infix expression (like `a + b`, `x > 5`).
    fn parse_infix(&mut self, left: AstNode) -> CompilerResult<AstNode> {
        let operator_location = self.get_location(); // Location of the operator/paren/dot
        let token_info = self.current_token_info.ok_or_else(|| {
            CompilerError::syntax_error(
                "Unexpected end of file while parsing infix expression",
                self.last_location.clone(),
            )
        })?;

        match &token_info.kind {
            TokenKind::Operator(op) => {
                let precedence = self.current_precedence();
                self.advance(); // Consume the operator
                let right = self.parse_expression_with_precedence(precedence)?;
                Ok(AstNode::BinaryOperation {
                    op: op.clone(),
                    left: Box::new(left),
                    right: Box::new(right),
                    location: operator_location,
                })
            }
            TokenKind::Keyword(kw) if kw == "in" => {
                let precedence = self.current_precedence();
                self.advance(); // Consume 'in'
                let right = self.parse_expression_with_precedence(precedence)?;
                Ok(AstNode::BinaryOperation {
                    op: "in".to_string(),
                    left: Box::new(left),
                    right: Box::new(right),
                    location: operator_location,
                })
            }
            TokenKind::LParen => {
                // This is a function call: left(arg1, arg2, ...)
                self.advance(); // Consume '('
                let mut arguments = Vec::new();
                self.skip_call_layout();
                if !self.check(&TokenKind::RParen) {
                    loop {
                        arguments.push(self.parse_call_argument()?);
                        self.skip_call_layout();
                        if self.check(&TokenKind::Comma) {
                            self.advance(); // Consume ','
                            self.skip_call_layout();
                            if self.check(&TokenKind::RParen) {
                                break;
                            }
                            continue;
                        }
                        if self.check(&TokenKind::RParen) {
                            break;
                        }
                        self.consume(
                            &TokenKind::Comma,
                            "Expected ',' or ')' after function argument",
                        )?;
                    }
                }
                self.consume(&TokenKind::RParen, "Expected ')' after function arguments")?;

                Ok(AstNode::FunctionCall {
                    function: Box::new(left),
                    arguments,
                    location: operator_location, // Location of '('
                    resolved_return_type: None,  // Set to None during parsing
                })
            }
            TokenKind::Dot => {
                // This is field access: left.field
                self.advance(); // Consume '.'
                let field_name_token = self.consume(
                    &TokenKind::Identifier("".to_string()),
                    "Expected field name after '.'",
                )?;
                let field_name = match &field_name_token.kind {
                    TokenKind::Identifier(name) => name.clone(),
                    _ => unreachable!(), // consume ensures it's an identifier
                };

                Ok(AstNode::FieldAccess {
                    object: Box::new(left),
                    field_name,
                    location: operator_location, // Location of '.'
                })
            }
            TokenKind::LBracket => {
                // Index access left[i] or slice left[a:b] (Pythonic, both
                // bounds optional). Slices lower to the builtin slice().
                self.advance(); // Consume '['

                let slice_bound_default =
                    |value: u128, location: &SourceLocation| AstNode::Literal {
                        value: Value::Int { value, kind: None },
                        location: location.clone(),
                    };
                let slice_start_default =
                    |location: &SourceLocation| slice_bound_default(i64::MAX as u128, location);
                let slice_stop_default =
                    |location: &SourceLocation| slice_bound_default(i64::MAX as u128, location);
                let slice_step_default =
                    |location: &SourceLocation| slice_bound_default(1, location);

                let start = if self.check(&TokenKind::Colon) {
                    slice_start_default(&operator_location)
                } else {
                    self.parse_expression()?
                };

                if self.check(&TokenKind::Colon) {
                    self.advance(); // Consume ':'
                    let stop = if self.check(&TokenKind::RBracket) || self.check(&TokenKind::Colon)
                    {
                        slice_stop_default(&operator_location)
                    } else {
                        self.parse_expression()?
                    };
                    let step = if self.check(&TokenKind::Colon) {
                        self.advance(); // Consume ':'
                        if self.check(&TokenKind::RBracket) {
                            slice_step_default(&operator_location)
                        } else {
                            self.parse_expression()?
                        }
                    } else {
                        slice_step_default(&operator_location)
                    };
                    self.consume(&TokenKind::RBracket, "Expected ']' after slice")?;
                    return Ok(AstNode::FunctionCall {
                        function: Box::new(AstNode::Identifier(
                            "slice".to_string(),
                            operator_location.clone(),
                        )),
                        arguments: vec![left, start, stop, step],
                        location: operator_location,
                        resolved_return_type: None,
                    });
                }

                self.consume(&TokenKind::RBracket, "Expected ']' after index")?;

                Ok(AstNode::IndexAccess {
                    base: Box::new(left),
                    index: Box::new(start),
                    location: operator_location, // Location of '['
                })
            }
            _ => Err(CompilerError::syntax_error(
                format!(
                    "Expected infix operator, function call '(', field access '.', or index access '[', found {:?}",
                    token_info.kind
                ),
                token_info.location.clone(),
            )),
        }
    }

    fn parse_call_argument(&mut self) -> CompilerResult<AstNode> {
        if matches!(
            self.current_token_info,
            Some(TokenInfo {
                kind: TokenKind::Identifier(_),
                ..
            })
        ) && self.check_next(&TokenKind::Colon)
        {
            let name_token = self.advance().unwrap();
            let name = match &name_token.kind {
                TokenKind::Identifier(name) => name.clone(),
                _ => unreachable!(),
            };
            self.consume(&TokenKind::Colon, "Expected ':' after named argument")?;
            let value = self.parse_expression()?;
            return Ok(AstNode::NamedArgument {
                name,
                value: Box::new(value),
                location: name_token.location.clone(),
            });
        }

        self.parse_expression()
    }

    fn skip_call_layout(&mut self) {
        while self.check(&TokenKind::Newline)
            || self.check(&TokenKind::Indent)
            || self.check(&TokenKind::Dedent)
        {
            self.advance();
        }
    }

    // Main expression parsing function using Pratt parsing logic.
    fn parse_expression_with_precedence(&mut self, min_precedence: u8) -> CompilerResult<AstNode> {
        let mut left = self.parse_prefix()?;

        // The loop condition checks precedence.
        // For function calls, '(' has precedence 7.
        // For field access, '.' has precedence 8.
        // For binary operators, they have precedence 1-6.
        while min_precedence < self.current_precedence() {
            // If the next token is an infix operator, '(', or '.' with higher precedence, parse it.
            left = self.parse_infix(left)?;
        }

        if min_precedence == 0 {
            if let Some(TokenInfo {
                kind: TokenKind::Operator(op),
                location,
            }) = self.current_token_info
            {
                let replacement = match op.as_str() {
                    "&&" => Some("and"),
                    "||" => Some("or"),
                    _ => None,
                };

                if let Some(replacement) = replacement {
                    return Err(CompilerError::syntax_error(
                        format!(
                            "Unsupported boolean operator '{op}'. Use '{replacement}' instead."
                        ),
                        location.clone(),
                    )
                    .with_hint(format!(
                        "Stoffel uses Pythonic boolean syntax: replace '{op}' with '{replacement}'"
                    )));
                }
            }
        }

        Ok(left)
    }

    // Public entry point for expression parsing.
    fn parse_expression(&mut self) -> CompilerResult<AstNode> {
        self.parse_expression_with_precedence(0)
    }

    // Handles expression statements (e.g., assignments, function calls)
    fn parse_expression_statement(&mut self) -> CompilerResult<AstNode> {
        let start_location = self.get_location();
        let expr = self.parse_expression()?;

        // Check for tuple unpacking pattern: a, b = expr
        // This is not supported in Stoffel-Lang
        if self.check(&TokenKind::Comma) {
            // Look ahead to see if this could be tuple unpacking
            // Pattern: identifier, identifier... = expr
            if matches!(expr, AstNode::Identifier(..)) {
                return Err(CompilerError::syntax_error(
                    "Tuple unpacking is not supported",
                    start_location,
                )
                .with_hint(
                    "Assign to a single variable instead of multiple comma-separated variables",
                ));
            }
        }

        // Check for compound assignment operators: +=, -=, *=, /=, %=
        // These are desugared into: x = x op value
        if let Some(TokenInfo {
            kind: TokenKind::Operator(op),
            location: op_location,
        }) = self.current_token_info
        {
            if let Some(base_op) = match op.as_str() {
                "+=" => Some("+"),
                "-=" => Some("-"),
                "*=" => Some("*"),
                "/=" => Some("/"),
                "%=" => Some("%"),
                _ => None,
            } {
                let op_location = op_location.clone();
                self.advance(); // Consume the compound operator
                let rhs = self.parse_expression()?;

                // Expect newline, EOF, or Dedent after the statement
                if !self.check(&TokenKind::Newline)
                    && !self.check(&TokenKind::Eof)
                    && !self.check(&TokenKind::Dedent)
                    && !self.check(&TokenKind::RParen)
                {
                    return Err(CompilerError::syntax_error(
                        format!(
                            "Expected newline, EOF, or dedent after compound assignment, found {:?}",
                            self.current_token_info
                        ),
                        self.get_location(),
                    ));
                }

                // Desugar: x += y  =>  x = x + y
                let binary_op = AstNode::BinaryOperation {
                    op: base_op.to_string(),
                    left: Box::new(expr.clone()),
                    right: Box::new(rhs),
                    location: op_location,
                };

                return Ok(AstNode::Assignment {
                    target: Box::new(expr),
                    value: Box::new(binary_op),
                    location: start_location,
                });
            }
        }

        // Could be assignment: expr = value
        if self.check(&TokenKind::Assign) {
            self.advance(); // Consume '='
            let value = self.parse_expression()?;
            // Expect newline, EOF, or Dedent after the statement
            if !self.check(&TokenKind::Newline)
                && !self.check(&TokenKind::Eof)
                && !self.check(&TokenKind::Dedent)
                && !self.check(&TokenKind::RParen)
            /* Allow in expr lists */
            {
                return Err(CompilerError::syntax_error(
                    format!(
                        "Expected newline, EOF, or dedent after assignment, found {:?}",
                        self.current_token_info
                    ),
                    self.get_location(),
                ));
            }
            Ok(AstNode::Assignment {
                target: Box::new(expr),
                value: Box::new(value),
                location: start_location, // Use location of the target expression start
            })
        } else {
            // Assume it's just an expression used as a statement (e.g., function call)
            // Expect newline, EOF, or Dedent after the statement
            if !self.check(&TokenKind::Newline)
                && !self.check(&TokenKind::Eof)
                && !self.check(&TokenKind::Dedent)
                && !self.check(&TokenKind::RParen)
            /* Allow in expr lists */
            {
                return Err(CompilerError::syntax_error(
                    format!(
                        "Expected newline, EOF, or dedent after expression statement, found {:?}",
                        self.current_token_info
                    ),
                    self.get_location(),
                ));
            }
            Ok(expr)
        }
    }

    // Parses type annotations (e.g., int, string, MyObject, List[int], secret int)
    // IMPORTANT: This function *only* parses the type name/structure itself.
    // It handles the optional 'secret' keyword internally.
    fn parse_type_annotation(&mut self) -> CompilerResult<AstNode> {
        let type_location = self.get_location(); // Location of 'secret' or the type identifier
        let mut is_secret = false;
        if self.check_keyword("secret") {
            self.advance(); // Consume 'secret'
            is_secret = true;
        }

        // Now parse the actual type
        let base_type = match &self.current_token_info {
            Some(TokenInfo {
                kind: TokenKind::Identifier(name),
                ..
            }) => {
                let base_name = name.clone();
                self.advance(); // Consume identifier

                // Check for generic type parameters: List[int], Dict[string, int]
                if self.check(&TokenKind::LBracket) {
                    self.advance(); // Consume '['

                    let normalized_base = match base_name.as_str() {
                        "List" => {
                            self.report_recoverable_error(
                                CompilerError::syntax_error(
                                    format!("Unknown generic type: {}", base_name),
                                    type_location.clone(),
                                )
                                .with_hint(
                                    "Did you mean 'list'? Generic types use lowercase Python spelling",
                                ),
                            )?;
                            "list"
                        }
                        "Dict" => {
                            self.report_recoverable_error(
                                CompilerError::syntax_error(
                                    format!("Unknown generic type: {}", base_name),
                                    type_location.clone(),
                                )
                                .with_hint(
                                    "Did you mean 'dict'? Generic types use lowercase Python spelling",
                                ),
                            )?;
                            "dict"
                        }
                        other => other,
                    };

                    match normalized_base {
                        "list" => {
                            let element_type = self.parse_type_annotation()?;
                            self.consume(
                                &TokenKind::RBracket,
                                "Expected ']' after list element type",
                            )?;
                            AstNode::ListType(Box::new(element_type))
                        }
                        "dict" => {
                            let key_type = self.parse_type_annotation()?;
                            self.consume(
                                &TokenKind::Comma,
                                "Expected ',' between dict key and value types",
                            )?;
                            let value_type = self.parse_type_annotation()?;
                            self.consume(
                                &TokenKind::RBracket,
                                "Expected ']' after dict value type",
                            )?;
                            AstNode::DictType {
                                key_type: Box::new(key_type),
                                value_type: Box::new(value_type),
                                location: type_location.clone(),
                            }
                        }
                        _ => {
                            // General generic type: Name[T1, T2, ...]
                            let mut type_params = Vec::new();
                            loop {
                                type_params.push(self.parse_type_annotation()?);
                                if self.check(&TokenKind::RBracket) {
                                    break;
                                }
                                self.consume(
                                    &TokenKind::Comma,
                                    "Expected ',' between type parameters",
                                )?;
                            }
                            self.consume(
                                &TokenKind::RBracket,
                                "Expected ']' after type parameters",
                            )?;
                            AstNode::GenericType {
                                base_name,
                                type_params,
                                location: type_location.clone(),
                            }
                        }
                    }
                } else {
                    // Simple type identifier
                    AstNode::Identifier(base_name, type_location.clone())
                }
            }
            _ => {
                let (found_str, location) = match self.current_token_info {
                    Some(token) => (format!("{:?}", token), token.location.clone()),
                    None => ("end of file".to_string(), self.last_location.clone()),
                };

                return Err(CompilerError::syntax_error(
                    format!(
                        "Expected type name identifier after 'secret' (if present), found {}",
                        found_str
                    ),
                    location,
                ));
            }
        };

        // Wrap in SecretType if needed
        if is_secret {
            Ok(AstNode::SecretType(Box::new(base_type)))
        } else {
            Ok(base_type)
        }
    }

    fn parse_variable_declaration(&mut self) -> CompilerResult<AstNode> {
        let start_location = self.get_location(); // Location of 'var'
                                                  // Only allow 'var' now. If someone writes 'let', we should have errored earlier,
                                                  // but double-check here defensively.
        if self.check_keyword("var") {
            self.advance(); // Consume 'var'
        } else if matches!(self.current_token_info, Some(TokenInfo { kind: TokenKind::Identifier(id), .. }) if id == "let")
        {
            let loc = self.get_location();
            return Err(CompilerError::syntax_error(
                "The 'let' keyword is no longer supported",
                loc,
            )
            .with_hint("Use 'var' for variable declarations"));
        } else {
            // Should not reach here if caller used correct entry points
            return Err(CompilerError::syntax_error(
                "Expected 'var' to start a variable declaration",
                self.get_location(),
            ));
        }
        let is_mutable = true; // With only 'var', declarations are always mutable

        let name_token = self.consume(
            &TokenKind::Identifier("".to_string()),
            "Expected variable name",
        )?;
        let name = match name_token {
            TokenInfo {
                kind: TokenKind::Identifier(n),
                ..
            } => n.clone(),
            _ => unreachable!(), // consume ensures it's an identifier
        };

        if self.check(&TokenKind::Comma) {
            return Err(CompilerError::syntax_error(
                "Tuple unpacking is not supported: a declaration binds exactly one variable",
                self.get_location(),
            )
            .with_hint(
                "Declare each variable on its own line, e.g. 'var a = 1' then 'var b = 2'",
            ));
        }

        // Parse optional type annotation
        let type_annotation = if self.check(&TokenKind::Colon) {
            self.advance(); // Consume ':'
            Some(Box::new(self.parse_type_annotation()?))
        } else {
            None
        };

        let mut value = None;
        if self.check(&TokenKind::Assign) {
            self.advance(); // Consume '='
            value = Some(Box::new(self.parse_expression()?));
        } else if type_annotation.is_none() {
            let location = self.get_location();
            return Err(CompilerError::syntax_error(
                "Variable declaration needs either a type annotation or an initial value",
                location,
            )
            .with_hint("Add a type annotation with ':' or initialize with '='"));
        }

        // Expect newline, EOF, or Dedent after declaration
        if !self.check(&TokenKind::Newline)
            && !self.check(&TokenKind::Eof)
            && !self.check(&TokenKind::Dedent)
            && !self.check(&TokenKind::RParen)
        /* Allow in expr lists */
        {
            return Err(CompilerError::syntax_error(
                format!(
                    "Expected newline, EOF, or dedent after variable declaration, found {:?}",
                    self.current_token_info
                ),
                self.get_location(),
            ));
        }

        Ok(AstNode::VariableDeclaration {
            name,
            type_annotation,
            value,
            is_mutable, // always true now
            is_secret: false,
            location: start_location, // Use location of 'var'
        })
    }

    // Parses a pragma block like {. ident1 . ident2: value .}
    fn parse_pragma(&mut self) -> CompilerResult<Vec<Pragma>> {
        self.consume(&TokenKind::LPragma, "Expected '{.' to start pragma")?;
        let mut pragmas = Vec::new();
        loop {
            if self.check(&TokenKind::RPragma) {
                break;
            }
            let pragma_name = match self.current_token_info {
                Some(TokenInfo {
                    kind: TokenKind::Identifier(name),
                    ..
                })
                | Some(TokenInfo {
                    kind: TokenKind::Keyword(name),
                    ..
                }) => Some(name.clone()),
                _ => None,
            };

            if let Some(name) = pragma_name {
                let token = self.advance().unwrap();
                let pragma_location = token.location.clone();
                if self.check(&TokenKind::Colon) {
                    self.advance(); // Consume ':'
                    let value_node = self.parse_expression()?; // Parse the value expression
                    pragmas.push(Pragma::KeyValue(
                        name,
                        Box::new(value_node),
                        pragma_location,
                    ));
                } else {
                    pragmas.push(Pragma::Simple(name, pragma_location));
                }
            } else {
                return Err(CompilerError::syntax_error(
                    "Expected identifier or keyword for pragma name",
                    self.get_location(),
                ));
            }

            // Consume optional separator dot or expect end
            if self.check(&TokenKind::Dot) {
                self.advance(); // Consume '.'
            } else if !self.check(&TokenKind::RPragma) {
                return Err(CompilerError::syntax_error(
                    "Expected '.' separator or '.}' to end pragma",
                    self.get_location(),
                ));
            } else {
                // RPragma will be consumed next iteration or at the end
            }
        }
        self.consume(&TokenKind::RPragma, "Expected '.}' to end pragma")?;
        Ok(pragmas)
    }

    // Helper to get current location
    fn get_location(&self) -> SourceLocation {
        self.current_token_info
            .map(|info| info.location.clone())
            .unwrap_or_else(|| self.last_location.clone()) // Use last known location if at EOF
    }
}

pub fn parse(tokens: &[TokenInfo], filename: &str) -> CompilerResult<AstNode> {
    let mut parser = Parser::new(tokens, filename, false);
    // The top-level parsing function (e.g., parse_program or parse_module)
    let root_node = parser.parse_program()?;

    // Check if all tokens were consumed (except EOF)
    if !parser.check(&TokenKind::Eof) {
        let (found_str, location) = match parser.current_token_info {
            Some(token) => (format!("{:?}", token), token.location.clone()),
            None => ("end of file".to_string(), parser.last_location.clone()),
        };

        Err(CompilerError::syntax_error(
            format!("Unexpected token after parsing finished: {}", found_str),
            location,
        ))
    } else {
        Ok(root_node)
    }
}

#[derive(Debug, Clone)]
pub struct ParseOutput {
    pub ast: AstNode,
    pub errors: Vec<CompilerError>,
}

pub fn parse_recovering(tokens: &[TokenInfo], filename: &str) -> ParseOutput {
    let mut parser = Parser::new(tokens, filename, true);
    let root_node = match parser.parse_program() {
        Ok(root) => root,
        Err(error) => {
            let error_location = error.location.clone();
            parser.errors.push(error);
            parser.synchronize_after_error(&error_location);
            AstNode::Block(Vec::new())
        }
    };

    if !parser.check(&TokenKind::Eof) {
        let (found_str, location) = match parser.current_token_info {
            Some(token) => (format!("{:?}", token), token.location.clone()),
            None => ("end of file".to_string(), parser.last_location.clone()),
        };

        parser.errors.push(CompilerError::syntax_error(
            format!("Unexpected token after parsing finished: {}", found_str),
            location,
        ));
    }

    ParseOutput {
        ast: root_node,
        errors: parser.errors,
    }
}
