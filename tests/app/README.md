# App unit tests

These tests are kept outside `src/app.rs` but are compiled as child modules of
`app` through `#[path = "..."]` declarations. This preserves access to private
application helpers without exposing them as production APIs.

Each directory groups tests by feature. Broader terminal areas use another
directory level for keyboard input, paste handling, protocol behavior,
selection, colors, and SFTP sorting.
