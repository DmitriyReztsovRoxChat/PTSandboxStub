# PTSandboxStub

Локальная заглушка публичного API PT Sandbox 5.12.

Контракт: см. документацию PT
  https://help.ptsecurity.com/ru-RU/projects/sb/5.12/developer/5105612427
  https://help.ptsecurity.com/ru-RU/projects/sb/5.12/developer/5040429451

Вердикт по имени файла (поле file_name в createScanTask):
  stem без расширения должен точно совпадать с SKIP, PASS, FAIL или ERROR (регистр
  важен), расширение — из allowlist (allowed_upload_extensions.json.
  Иначе — ответ как для чистого файла (PASS).

Важно про SKIP: в приложении PTSandboxResult.SKIP возвращается только если в
настройках аккаунта пустой pt_sandbox.url — до HTTP это не доходит. Имя файла
SKIP здесь обрабатывается так же, как PASS (успешный скан CLEAN), только для
единообразия имён в ручных тестах.

Локально из контейнеров доступна на http://host.docker.internal:8090
