# Results: haiku, 10 run(s) per task and condition

| Task | Condition | Safe | Correct | Migration failed |
|---|---|---|---|---|
| Private notes | baseline | 10/10 | 10/10 | 0/10 |
| Private notes | with-guide | 10/10 | 10/10 | 0/10 |
| Team projects with admins | baseline | 10/10 | 10/10 | 0/10 |
| Team projects with admins | with-guide | 10/10 | 9/10 | 1/10 |
| Support tickets with an admin flag | baseline | 10/10 | 10/10 | 0/10 |
| Support tickets with an admin flag | with-guide | 10/10 | 9/10 | 1/10 |
| Blog with drafts | baseline | 10/10 | 10/10 | 0/10 |
| Blog with drafts | with-guide | 10/10 | 10/10 | 0/10 |
| Documents shared between users | baseline | 10/10 | 9/10 | 0/10 |
| Documents shared between users | with-guide | 8/10 | 3/10 | 0/10 |
| Shop with anonymous sign-ins | baseline | 10/10 | 10/10 | 0/10 |
| Shop with anonymous sign-ins | with-guide | 10/10 | 10/10 | 0/10 |

- **baseline:** 60/60 safe, 59/60 correct, 0/60 migrations failed, cost $0.10
- **with-guide:** 58/60 safe, 51/60 correct, 2/60 migrations failed, cost $0.22

## What went wrong

- teams / with-guide #3: migration failed: syntax error at or near "```"
- tickets / with-guide #10: migration failed: schema "private" does not exist
- shares / baseline #9: broken, bob reads his and the one shared with him: misses 1
- shares / baseline #9: broken, carol reads the one shared with her: misses 2
- shares / baseline #9: broken, editor carol changes content: blocked, 0 row(s)
- shares / with-guide #1: broken, alice reads her documents: misses 1, 2 (error: infinite recursion detected in policy for relation "documents")
- shares / with-guide #1: broken, bob reads his and the one shared with him: misses 1, 3 (error: infinite recursion detected in policy for relation "documents")
- shares / with-guide #1: broken, carol reads the one shared with her: misses 2 (error: infinite recursion detected in policy for relation "documents")
- shares / with-guide #1: broken, editor carol changes content: blocked, error: infinite recursion detected in policy for relation "documents"
- shares / with-guide #1: broken, owner alice shares with carol: blocked, error: infinite recursion detected in policy for relation "document_shares"
- shares / with-guide #2: broken, editor carol changes content: blocked, error: infinite recursion detected in policy for relation "documents"
- shares / with-guide #3: LEAK, editor carol takes ownership: went through, 1 row(s)
- shares / with-guide #5: LEAK, editor carol takes ownership: went through, 1 row(s)
- shares / with-guide #7: broken, editor carol changes content: blocked, error: infinite recursion detected in policy for relation "documents"
- shares / with-guide #8: broken, editor carol changes content: blocked, error: infinite recursion detected in policy for relation "documents"
- shares / with-guide #10: broken, alice reads her documents: misses 1, 2 (error: infinite recursion detected in policy for relation "documents")
- shares / with-guide #10: broken, bob reads his and the one shared with him: misses 1, 3 (error: infinite recursion detected in policy for relation "documents")
- shares / with-guide #10: broken, carol reads the one shared with her: misses 2 (error: infinite recursion detected in policy for relation "documents")
- shares / with-guide #10: broken, editor carol changes content: blocked, error: infinite recursion detected in policy for relation "documents"
- shares / with-guide #10: broken, owner alice shares with carol: blocked, error: infinite recursion detected in policy for relation "document_shares"
