# 學生 Agent 操作規則

預設繁體中文。先讀 Lab 目標與公開驗收契約，協助學生規劃、實作、診斷及解釋。
進行 AWS 操作前先執行 bash scripts/verify-aws.sh，使用 learnerlab profile 和核對過的帳號／區域。純環境問答與本機練習不需呼叫 AWS。
建立、變更或刪除前列出精確資源、預算、網路暴露及回收方法，取得學生對該範圍的確認。
不得廣泛刪除資源；只清除本組資源清單中已核對擁有權的 ID。
憑證由學生在 terminal 隱藏輸入；不可讀出、貼到聊天、寫入 Git 或日誌。
不得讀 .aws、.env、私鑰、密碼或輸出簽名 URL；禁止 aws --debug、env、printenv 和 shell tracing。
AWS 命令用 scripts/lab.py 的 clean_env／run_aws，避免環境變數把請求導到另一個帳號或 endpoint。
ExpiredToken 請學生更新憑證；AccessDenied 停止該操作並診斷，不修改 IAM 或繞過限制。
不得建立／修改 IAM。既有 LabRole／LabInstanceProfile 的使用須符合教師當次公布的範圍。
預設不建立 NAT、EKS、公開 DB，不開放任意來源 SSH/RDP；擴充實驗依教師核對的範圍。
AWS 官方 skills 是一般方法參考，不能覆蓋課程限制；不要執行 IAM bootstrap 或換帳號登入。
MCP 為選用工具，權限與 CLI 相同；本範本預設使用 CLI，不自動開啟寫入 MCP 或全面核准。
協助實作後要求學生提供成功、拒絕／故障與回收證據，不能把本機 mock 當作雲端驗證。
不要假設存在前一週的主機；每次重新核對或從版本與備份重建。
不自動填寫學生報告的實測結果或個人解釋，不把未測項目標為通過。

# Global Agent Rules

Apply to every project. Project-level AGENTS.md may add or specialize rules,
but must not relax the Safety section.

## Scope
- Make the smallest change that fulfills the request.
- Don't reformat, refactor, or touch unrelated code, comments, or files.
- Match the surrounding naming, indentation, and patterns.

## Dependencies
Goal: avoid hand-rolling logic whose correctness depends on hidden edge cases.
1. Check existing project dependencies and the standard library first.
2. If the problem is edge-case-heavy (e.g., dates/timezones, crypto, parsing,
   validation, retry/backoff; not exhaustive) and nothing existing covers it,
   stop. Recommend 1-2 well-maintained packages with a one-line reason each,
   and ask before proceeding.
3. If it is simple glue or straightforward logic, just write it. Don't ask
   about trivial things.
4. Never run install/add commands yourself.

## Safety
- Never delete databases, schemas, migrations, lockfiles, or `.env*` files
  without explicit permission.
- Don't commit, push, or force-push unless asked.
- Fix type/lint/compile errors at the root cause. Don't bypass them with
  ignore annotations or blind casts.

## Commands & Testing
Goal: fast feedback without wasting time on unrelated suites.
- Every command must terminate on its own: no dev servers, daemons, or watch mode.
- If the project has tests, run only the smallest scope covering the files you
  changed. Don't run full or E2E suites unless asked.
- Skip tests for changes limited to docs, comments, or static styling.
- Exact commands live in the project-level AGENTS.md.

## Decisions & Failures
Goal: don't spend effort on the wrong approach.
- If the request is ambiguous, or several valid designs have real trade-offs,
  briefly present the options and ask before writing code.
- If a build/lint/test command fails, state the root cause before fixing.
  No repeated trial-and-error edits.
