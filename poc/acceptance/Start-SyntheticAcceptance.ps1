[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$compose = Join-Path $PSScriptRoot 'docker-compose.yml'
$secretDirectory = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\runtime\acceptance'))
[IO.Directory]::CreateDirectory($secretDirectory) | Out-Null
foreach ($name in 'zmodo_secret_key', 'zmodo_internal_token') {
    $bytes = [byte[]]::new(32)
    $generator = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $generator.GetBytes($bytes) } finally { $generator.Dispose() }
    [IO.File]::WriteAllText(
        (Join-Path $secretDirectory $name),
        [Convert]::ToBase64String($bytes),
        [Text.UTF8Encoding]::new($false)
    )
}

try {
    docker compose -f $compose up -d --build --wait
    if ($LASTEXITCODE) { throw 'Der synthetische Camera-Hub-Stack konnte nicht gestartet werden.' }
    $env:PLAYWRIGHT_BASE_URL = 'http://127.0.0.1:18091'
    $env:RUN_SYNTHETIC_ACCEPTANCE = '1'
    npx playwright test poc/e2e/synthetic-stack.spec.js --project=chrome-acceptance
    if ($LASTEXITCODE) { throw 'Die synthetische Browserabnahme ist fehlgeschlagen.' }
} finally {
    Remove-Item Env:PLAYWRIGHT_BASE_URL -ErrorAction SilentlyContinue
    Remove-Item Env:RUN_SYNTHETIC_ACCEPTANCE -ErrorAction SilentlyContinue
    docker compose -f $compose down -v --remove-orphans
}
