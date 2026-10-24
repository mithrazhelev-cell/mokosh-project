# MOKOSH — договор за explicit runtime path initialization

Статус: Stage 2.24 — normal-main-GUI import без filesystem mutation и explicit
startup preparation; няма recovery source, secret intake или operation
authority.

## 1. Причина

След Stage 2.23 normal `import mokosh_gui` има ограничена recovery dependency
граница, но legacy `seed_manager.py` зарежда `mokosh_paths.py`.
`mokosh_paths.py` извиква `ensure_private_data_dir()` на module level и така
самото import-ване може да създаде `MOKOSH_DATA_DIR` или да промени правата на
вече съществуваща директория.

Това не е recovery операция, но е неявна filesystem mutation преди explicit
application startup. Module inspection, test discovery или импорт от друг код
не трябва самостоятелно да променя filesystem state.

## 2. Frozen boundary

Stage 2.24 премахва module-level извикването от `mokosh_paths.py`.
`APP_DIR`, `DATA_DIR` и `ensure_private_data_dir()` запазват exact съществуващия
си contract. Само моментът на извикване се променя:

- normal `import mokosh_gui` и direct `import mokosh_paths` не създават и не
  chmod-ват runtime директория;
- `mokosh_gui.main()` извиква `ensure_private_data_dir()` точно веднъж;
- conditional prepared-review binding се валидира преди filesystem
  preparation;
- preparation завършва преди `tk.Tk()` и преди създаване на widget;
- failure при directory creation остава fail-closed и не отваря GUI.

Това запазва съществуващата normal-launch preparation, но я прави explicit и
наблюдаема application boundary вместо import side effect.

## 3. Непроменено поведение

Stage 2.24 не променя:

- стойността или resolution semantics на `APP_DIR` и `DATA_DIR`;
- `ensure_private_data_dir()` mkdir/chmod contract;
- `MOKOSH_DATA_DIR` environment override;
- launcher `umask 077` и exact Python runtime selection;
- GUI text, layout, geometry, colors, buttons или events;
- Stage 2.18 conditional review и Stage 2.20 normal entry behavior;
- legacy seed/contact file formats или cryptographic behavior;
- `SAFETY_MODE=True`.

Standalone legacy writer functions продължават да създават собствените си
директории по съществуващия си contract. Този stage не преработва legacy
storage.

## 4. Trust boundaries и забрани

Stage 2.24:

- не избира, не отваря и не подготвя recovery source;
- не приема password, recovery root/record, keyring, Vault ID, path или file;
- не свързва Stage 2.21 transition към GUI;
- не създава recovery session, binding, workflow или presentation;
- не извиква Stage 2.8 reconciliation, unlock, candidate, setup, publish,
  cleanup, encryption или decryption;
- не променя `seed_manager.py`, `contacts_core.py`, crypto/Vault/recovery core;
- няма network, telemetry, logging, Guardian, update или licensing;
- не предоставя operation authority и няма automatic transition.

Единствената filesystem mutation в scope е преместването на съществуващата
runtime-directory preparation от import time към explicit `main()` startup.

## 5. Задължителни тестове

- fresh-process normal GUI import с absent runtime directory: directory остава
  absent;
- fresh-process normal GUI import с existing directory: mode остава
  непроменен;
- direct paths import няма module-level ensure call;
- explicit ensure създава absent directory с private mode;
- explicit ensure затяга existing directory до private mode;
- `main()` извиква preparation преди `tk.Tk()`;
- preparation failure блокира `tk.Tk()`;
- invalid conditional binding се отказва преди preparation;
- exact one-call/static reachability boundary;
- byte-exact GUI text registries и `SAFETY_MODE=True`;
- no recovery source/operation imports;
- byte-exact launcher, crypto, seed, contacts, recovery contracts и runtime
  requirements;
- full regression без skipped security tests.

## 6. Ограничения

Това е bounded import/startup side-effect hardening. То не е redesign или
security approval на legacy seed/contact storage, filesystem certification,
platform certification, independent audit, legal conclusion или доказателство
за recovery success.

Известните legacy storage рискове и file-pipeline/lifecycle import cycle
остават отделни бъдещи review scopes. Recovery source selection/preparation и
всяка operation authority също изискват fresh review и отделен frozen stage.
