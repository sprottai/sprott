//! The 2.0 move against temp homes and a fake service manager. No test here
//! reaches the real user bus, a real daemon or the developer's home.

use super::*;
use crate::cli::agent::env_value;
use std::collections::BTreeMap;
use std::sync::Mutex;

// ── a fake machine ───────────────────────────────────────────────────────────

#[derive(Default)]
struct World {
    /// The daemon reached through the old unit, plist or pid answers.
    old_running: bool,
    /// The daemon started by the move answers.
    new_running: bool,
    /// The old daemon ignores every stop.
    stubborn: bool,
    detached_pid: Option<u32>,
    calls: Vec<String>,
}

#[derive(Default)]
struct FakeSys(Mutex<World>);

impl FakeSys {
    fn running() -> Self {
        FakeSys(Mutex::new(World {
            old_running: true,
            ..Default::default()
        }))
    }
    fn calls(&self) -> Vec<String> {
        self.0.lock().unwrap().calls.clone()
    }
    fn count(&self, call: &str) -> usize {
        self.calls().iter().filter(|c| *c == call).count()
    }
    fn new_running(&self) -> bool {
        self.0.lock().unwrap().new_running
    }
}

impl Sys for FakeSys {
    fn answers(&self, _authority: &str) -> bool {
        let w = self.0.lock().unwrap();
        w.old_running || w.new_running
    }
    fn pid_live(&self, pid: u32) -> bool {
        let w = self.0.lock().unwrap();
        w.detached_pid == Some(pid) && w.old_running
    }
    fn terminate(&self, pid: u32) {
        let mut w = self.0.lock().unwrap();
        w.calls.push(format!("kill {pid}"));
        if !w.stubborn && w.detached_pid == Some(pid) {
            w.old_running = false;
        }
    }
    fn systemctl(&self, args: &[&str]) -> Result<(), String> {
        let mut w = self.0.lock().unwrap();
        w.calls.push(format!("systemctl {}", args.join(" ")));
        match args {
            ["stop", u] if *u == OLD_UNIT => {
                if !w.stubborn {
                    w.old_running = false
                }
            }
            ["disable", "--now", u] if *u == OLD_UNIT => w.old_running = false,
            ["start", u] if *u == names::SYSTEMD_UNIT => w.new_running = true,
            ["start", u] if *u == OLD_UNIT => w.old_running = true,
            _ => {}
        }
        Ok(())
    }
    fn launchctl(&self, args: &[&str]) -> Result<(), String> {
        let mut w = self.0.lock().unwrap();
        w.calls.push(format!("launchctl {}", args.join(" ")));
        match args {
            ["bootout", s] if s.ends_with(OLD_LABEL) => {
                if !w.stubborn {
                    w.old_running = false
                }
            }
            ["kickstart", "-k", s] if s.ends_with(names::LAUNCHD_LABEL) => w.new_running = true,
            _ => {}
        }
        Ok(())
    }
    fn spawn_detached(&self, exe: &Path) -> Result<(), String> {
        let mut w = self.0.lock().unwrap();
        w.calls.push(format!("spawn {} serve", exe.display()));
        w.new_running = true;
        Ok(())
    }
    fn uid(&self) -> u32 {
        501
    }
    fn sleep(&self, _d: Duration) {}
}

// ── fixtures ─────────────────────────────────────────────────────────────────

struct Home {
    _tmp: tempfile::TempDir,
    home: PathBuf,
    unit_dir: PathBuf,
    agents: PathBuf,
}

impl Home {
    fn new(name: &str) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join(name);
        fs::create_dir_all(&home).unwrap();
        Home {
            unit_dir: home.join(".config/systemd/user"),
            agents: home.join("Library/LaunchAgents"),
            home,
            _tmp: tmp,
        }
    }
    fn h(&self) -> String {
        self.home.display().to_string()
    }
    fn old(&self) -> PathBuf {
        self.home.join(".safeclaw")
    }
    fn new_dir(&self) -> PathBuf {
        self.home.join(".sprott")
    }
    fn ctx<'a>(&self, sys: &'a FakeSys, platform: Platform) -> Ctx<'a> {
        Ctx {
            home: self.home.clone(),
            unit_dir: self.unit_dir.clone(),
            launch_agents: self.agents.clone(),
            platform,
            exe: PathBuf::from("/opt/sprott/bin/sprott"),
            sys,
            start_daemon: true,
            wait: Duration::from_secs(20),
            crash_after: None,
        }
    }
}

fn put(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn agent_env(identity: &str) -> String {
    format!(
        "SAFECLAW_BROKER_URL=http://127.0.0.1:23294\nSAFECLAW_AGENT_IDENTITY={}\n",
        env_value(identity)
    )
}

const VM_AGENT: &str = "Claude Code (VM)";

/// A 1.5 home as `sc setup` and `sc up` leave it.
fn seed_15(h: &Home) {
    let home = h.h();
    let old = h.old();
    put(
        &old.join("config.toml"),
        "daemon = \"http://127.0.0.1:23293\"\nvault = \"v1\"\n",
    );
    put(
        &old.join("agent.env"),
        &agent_env(&format!("{home}/.safeclaw/agents/codex/identity")),
    );
    put(
        &old.join("agents/codex/agent.env"),
        &agent_env(&format!("{home}/.safeclaw/agents/codex/identity")),
    );
    put(&old.join("agents/codex/identity"), "{\"v\":1}");
    put(
        &old.join("agents").join(VM_AGENT).join("agent.env"),
        &format!(
            "# from sc agent add\nexport SAFECLAW_BROKER_URL=http://127.0.0.1:23294\nSAFECLAW_AGENT_IDENTITY={}\nOTHER=1\n",
            env_value(&format!("{home}/.safeclaw/agents/{VM_AGENT}/identity"))
        ),
    );
    put(
        &old.join("setup/status.json"),
        &format!(
            "{{\"phase\":\"done\",\"state\":\"ok\",\"message\":\"See {home}/.safeclaw/setup/background.log\",\"pid\":1,\"updated_at\":2}}"
        ),
    );
    put(&old.join("state/egress-proxy"), "http://proxy.example:3128\n");
    put(&old.join("crypto/sc_sk.bin"), "key");
}

fn old_unit_text(h: &Home) -> String {
    let home = h.h();
    format!(
        "# Generated by safeclaw. Do not edit; re-run `sprott up` to refresh.\n\
         [Unit]\nDescription=Sprott daemon (user)\nAfter=network.target\n\n\
         [Service]\nType=simple\n\
         Environment=\"SAFECLAW_ADMIN_KEY=k3y\"\n\
         Environment=\"SAFECLAW_STATE_DIR={home}/.safeclaw/state\"\n\
         ExecStart={home}/.local/bin/sc serve\nRestart=on-failure\nRestartSec=5\n\n\
         [Install]\nWantedBy=default.target\n"
    )
}

fn seed_unit(h: &Home, text: &str, enabled: bool) {
    put(&h.unit_dir.join(OLD_UNIT), text);
    if enabled {
        let wants = h.unit_dir.join("default.target.wants");
        fs::create_dir_all(&wants).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(format!("../{OLD_UNIT}"), wants.join(OLD_UNIT)).unwrap();
    }
}

/// Every file under `dir`: relative path → bytes (a symlink → its target).
fn snapshot(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(dir: &Path, base: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let p = e.path();
            let rel = p.strip_prefix(base).unwrap().display().to_string();
            let meta = fs::symlink_metadata(&p).unwrap();
            if meta.file_type().is_symlink() {
                out.insert(
                    rel,
                    format!("-> {}", fs::read_link(&p).unwrap().display()).into_bytes(),
                );
            } else if meta.is_dir() {
                out.insert(format!("{rel}/"), Vec::new());
                walk(&p, base, out);
            } else {
                out.insert(rel, fs::read(&p).unwrap());
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(dir, dir, &mut out);
    out
}

/// A snapshot with the home path and the record's clock fields neutralised,
/// so two runs in different temp homes compare equal.
fn normalized(h: &Home) -> BTreeMap<String, String> {
    snapshot(&h.home)
        .into_iter()
        .map(|(k, v)| {
            let mut text = String::from_utf8_lossy(&v).replace(&h.h(), "<HOME>");
            if k.ends_with(RECORD) {
                let mut j: serde_json::Value = serde_json::from_str(&text).unwrap();
                j["at"] = 0.into();
                j["finished_at"] = 0.into();
                text = j.to_string();
            }
            (k, text)
        })
        .collect()
}

fn moved(outcome: Result<Outcome, Fail>) -> Report {
    match outcome {
        Ok(Outcome::Moved(r)) => r,
        other => panic!("expected a finished move, got {other:?}"),
    }
}

// ── states ───────────────────────────────────────────────────────────────────

#[test]
fn the_five_states_and_where_serve_waits() {
    let h = Home::new("u");
    assert_eq!(detect(&h.home), State::E);
    assert!(!serve_must_wait(&h.home));

    fs::create_dir(h.old()).unwrap();
    assert_eq!(detect(&h.home), State::A);
    assert!(serve_must_wait(&h.home));

    fs::create_dir(h.new_dir()).unwrap();
    assert_eq!(detect(&h.home), State::D);
    assert!(serve_must_wait(&h.home));

    put(&h.new_dir().join(RECORD), "{}");
    assert_eq!(detect(&h.home), State::C);
    assert!(!serve_must_wait(&h.home));

    fs::remove_dir(h.old()).unwrap();
    assert_eq!(detect(&h.home), State::E);

    put(&h.new_dir().join(MOVING), "{}");
    assert_eq!(detect(&h.home), State::B);
    assert!(!serve_must_wait(&h.home), "serve serves in state B");
    fs::create_dir(h.old()).unwrap();
    assert_eq!(detect(&h.home), State::B, "an unfinished move wins");
}

#[test]
fn version_git_credential_and_serve_never_move() {
    use clap::Parser;
    let parse = |args: &[&str]| crate::config::Cli::try_parse_from(args).unwrap().command;
    assert!(exempt(&parse(&["sprott", "version"])));
    assert!(exempt(&parse(&["sprott", "git-credential", "get"])));
    assert!(exempt(&parse(&["sprott", "serve"])));
    assert!(!exempt(&parse(&["sprott", "up"])));
    assert!(!exempt(&parse(&["sprott", "skill", "install"])));
    assert!(!exempt(&parse(&["sprott", "status"])));
}

#[test]
fn a_fresh_home_is_left_alone() {
    let h = Home::new("u");
    let sys = FakeSys::default();
    assert!(nothing_to_do(&h.home));
    assert_eq!(run(&h.ctx(&sys, Platform::Systemd)).unwrap(), Outcome::Nothing);
    assert!(snapshot(&h.home).is_empty(), "nothing created, not even the lock");
    assert!(sys.calls().is_empty());
}

// ── the whole move ───────────────────────────────────────────────────────────

#[test]
fn a_running_systemd_install_moves_and_comes_back_as_sprott_service() {
    let h = Home::new("Mia Li");
    seed_15(&h);
    let unit = old_unit_text(&h);
    seed_unit(&h, &unit, true);
    let before = snapshot(&h.old());
    let sys = FakeSys::running();

    let report = moved(run(&h.ctx(&sys, Platform::Systemd)));
    let home = h.h();
    let data = h.new_dir();

    assert_eq!(
        report_lines(&report),
        vec!["Moved ~/.safeclaw to ~/.sprott; the daemon is now sprott.service.".to_string()]
    );
    assert!(!h.old().exists());
    assert!(!data.join(MOVING).exists());
    assert!(!h.home.join(LOCK).exists(), "the lock goes once the move is done");

    // agent.env files: keys renamed, the leading path rewritten, quoted again.
    let codex = format!(
        "SPROTT_BROKER_URL=http://127.0.0.1:23294\nSPROTT_AGENT_IDENTITY={}\n",
        env_value(&format!("{home}/.sprott/agents/codex/identity"))
    );
    assert!(codex.contains("'"), "a home with a space is quoted");
    assert_eq!(read(&data.join("agent.env")), codex);
    assert_eq!(read(&data.join("agents/codex/agent.env")), codex);
    assert_eq!(
        read(&data.join("agents").join(VM_AGENT).join("agent.env")),
        format!(
            "# from sc agent add\nexport SPROTT_BROKER_URL=http://127.0.0.1:23294\nSPROTT_AGENT_IDENTITY={}\nOTHER=1\n",
            env_value(&format!("{home}/.sprott/agents/{VM_AGENT}/identity"))
        )
    );
    assert!(read(&data.join("setup/status.json"))
        .contains(&format!("See {home}/.sprott/setup/background.log")));

    // The originals, byte for byte, in pre-2.0/.
    for rel in [
        "agent.env",
        "agents/codex/agent.env",
        "agents/Claude Code (VM)/agent.env",
        "setup/status.json",
    ] {
        assert_eq!(
            fs::read(data.join(PRE_2).join(rel)).unwrap(),
            before[rel],
            "{rel}"
        );
    }
    // Everything else moved unchanged (the egress proxy setting included).
    for rel in ["config.toml", "agents/codex/identity", "state/egress-proxy", "crypto/sc_sk.bin"] {
        assert_eq!(fs::read(data.join(rel)).unwrap(), before[rel], "{rel}");
    }

    // The unit: the 2.0 template, the canonical binary, the env carried over.
    let new_unit = read(&h.unit_dir.join("sprott.service"));
    assert_eq!(
        new_unit,
        crate::cli::service::systemd_unit(
            "/opt/sprott/bin/sprott",
            &[
                "Environment=\"SPROTT_ADMIN_KEY=k3y\"".to_string(),
                format!("Environment=\"SPROTT_STATE_DIR={home}/.sprott/state\""),
            ]
        )
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(h.unit_dir.join("sprott.service")).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    assert!(!h.unit_dir.join(OLD_UNIT).exists());
    assert_eq!(read(&data.join(PRE_2).join(OLD_UNIT)), unit, "moved, not copied");

    assert_eq!(
        sys.calls(),
        [
            "systemctl stop safeclaw.service",
            "systemctl disable --now safeclaw.service",
            "systemctl daemon-reload",
            "systemctl enable sprott.service",
            "systemctl start sprott.service",
        ]
    );
    assert!(sys.new_running());

    let record: serde_json::Value = serde_json::from_str(&read(&data.join(RECORD))).unwrap();
    assert_eq!(record["was_running"], true);
    assert_eq!(record["was_enabled"], true);
    assert_eq!(record["manager"], "systemd");
    assert_eq!(record["binary"], "/opt/sprott/bin/sprott");
    assert_eq!(
        record["rewritten"],
        serde_json::json!([
            "pre-2.0/agent.env",
            "pre-2.0/agents/Claude Code (VM)/agent.env",
            "pre-2.0/agents/codex/agent.env",
            "pre-2.0/safeclaw.service",
            "pre-2.0/setup/status.json",
        ])
    );

    // Done once: the next command finds nothing to do.
    assert!(nothing_to_do(&h.home));
    assert_eq!(run(&h.ctx(&sys, Platform::Systemd)).unwrap(), Outcome::Nothing);
    assert_eq!(sys.calls().len(), 5);
}

#[test]
fn rewritten_agent_env_files_still_load_in_sh() {
    for name in ["Mia Li", "O'Brien", "plain"] {
        let h = Home::new(name);
        seed_15(&h);
        let sys = FakeSys::default();
        moved(run(&h.ctx(&sys, Platform::Systemd)));
        for file in [
            h.new_dir().join("agents/codex/agent.env"),
            h.new_dir().join("agents").join(VM_AGENT).join("agent.env"),
        ] {
            let out = std::process::Command::new("sh")
                .arg("-c")
                .arg(r#"set -a; . "$1"; set +a; printf '%s\n%s\n%s' "$SPROTT_BROKER_URL" "$SPROTT_AGENT_IDENTITY" "${SAFECLAW_AGENT_IDENTITY:-unset}""#)
                .arg("sh")
                .arg(&file)
                .env_remove("SAFECLAW_AGENT_IDENTITY")
                .output()
                .unwrap();
            assert!(out.status.success(), "{name}: {}", String::from_utf8_lossy(&out.stderr));
            let agent = file.parent().unwrap().file_name().unwrap().to_string_lossy().to_string();
            assert_eq!(
                String::from_utf8_lossy(&out.stdout),
                format!(
                    "http://127.0.0.1:23294\n{}/.sprott/agents/{agent}/identity\nunset",
                    h.h()
                ),
                "{name}"
            );
        }
    }
}

#[test]
fn agent_env_line_forms() {
    let home = Path::new("/home/a");
    let changed = |s: &str| EnvLine::Changed(s.to_string());
    for (line, want) in [
        ("SAFECLAW_BROKER_URL=http://127.0.0.1:23294", changed("SPROTT_BROKER_URL=http://127.0.0.1:23294")),
        (
            "SAFECLAW_AGENT_IDENTITY=/home/a/.safeclaw/agents/x/identity",
            changed("SPROTT_AGENT_IDENTITY=/home/a/.sprott/agents/x/identity"),
        ),
        (
            "export SAFECLAW_AGENT_IDENTITY=/home/a/.safeclaw/agents/x/identity",
            changed("export SPROTT_AGENT_IDENTITY=/home/a/.sprott/agents/x/identity"),
        ),
        (
            "SAFECLAW_AGENT_IDENTITY='~/.safeclaw/agents/x/identity'",
            changed("SPROTT_AGENT_IDENTITY='~/.sprott/agents/x/identity'"),
        ),
        // A path that only looks like ours keeps its value; the key still moves.
        ("SAFECLAW_DATA=/home/a/.safeclawx", changed("SPROTT_DATA=/home/a/.safeclawx")),
        ("OTHER=1", EnvLine::Same),
        ("# a comment", EnvLine::Same),
        ("", EnvLine::Same),
        // Forms `env_value` never writes: left, and reported.
        ("SAFECLAW_X=\"/home/a/.safeclaw/x\"", EnvLine::Left),
        ("SAFECLAW_X=~/.safeclaw/x", EnvLine::Left),
        ("# SAFECLAW_BROKER_URL=old", EnvLine::Left),
        ("FOO=/opt/.safeclaw/x", EnvLine::Left),
    ] {
        assert_eq!(rewrite_env_line(line, home), want, "{line}");
    }
    let spaced = Path::new("/Users/Mia Li");
    assert_eq!(
        rewrite_env_line("SAFECLAW_AGENT_IDENTITY='/Users/Mia Li/.safeclaw/agents/x/identity'", spaced),
        changed("SPROTT_AGENT_IDENTITY='/Users/Mia Li/.sprott/agents/x/identity'")
    );
    let quote = Path::new("/home/o'b");
    assert_eq!(
        rewrite_env_line("SAFECLAW_AGENT_IDENTITY='/home/o'\\''b/.safeclaw/agents/x/identity'", quote),
        changed("SPROTT_AGENT_IDENTITY='/home/o'\\''b/.sprott/agents/x/identity'")
    );
    // A broken quote is not a form we write.
    assert_eq!(rewrite_env_line("SAFECLAW_X='/home/a/.safeclaw/x", home), EnvLine::Left);
}

#[test]
fn lines_left_as_they_are_are_reported() {
    let h = Home::new("u");
    seed_15(&h);
    let hand = format!(
        "SAFECLAW_BROKER_URL=http://127.0.0.1:23294\r\nSAFECLAW_EXTRA=\"{}/.safeclaw/x\"\r\n",
        h.h()
    );
    put(&h.old().join("agents/hand/agent.env"), &hand);
    let sys = FakeSys::default();
    let report = moved(run(&h.ctx(&sys, Platform::Systemd)));
    assert_eq!(
        report.left,
        vec!["~/.sprott/agents/hand/agent.env line 2 still names SAFECLAW_ or ~/.safeclaw; edit it by hand.".to_string()]
    );
    assert_eq!(
        read(&h.new_dir().join("agents/hand/agent.env")),
        format!(
            "SPROTT_BROKER_URL=http://127.0.0.1:23294\r\nSAFECLAW_EXTRA=\"{}/.safeclaw/x\"\r\n",
            h.h()
        ),
        "CRLF kept, the hand-edited line byte-identical"
    );
    assert!(findings(&h.home, &h.unit_dir, &h.agents)
        .contains(&"~/.sprott/agents/hand/agent.env still names SAFECLAW_ or ~/.safeclaw; Sprott 2.0 reads SPROTT_ and ~/.sprott".to_string()));
}

// ── refusals ─────────────────────────────────────────────────────────────────

#[test]
fn a_daemon_that_will_not_stop_refuses_and_moves_nothing() {
    let h = Home::new("u");
    seed_15(&h);
    seed_unit(&h, &old_unit_text(&h), true);
    let old_before = snapshot(&h.old());
    let units_before = snapshot(&h.unit_dir);
    let sys = FakeSys::running();
    sys.0.lock().unwrap().stubborn = true;

    match run(&h.ctx(&sys, Platform::Systemd)) {
        Err(Fail::Refused(msg)) => assert_eq!(
            msg,
            "Sprott 2.0 could not move ~/.safeclaw: a daemon from before 2.0 is still running (http://127.0.0.1:23293).\n\
             Fix: stop it, then run: sprott up"
        ),
        other => panic!("{other:?}"),
    }
    assert_eq!(snapshot(&h.old()), old_before, "~/.safeclaw byte-identical");
    assert_eq!(snapshot(&h.unit_dir), units_before);
    assert!(!h.new_dir().exists());
    assert_eq!(
        sys.calls(),
        ["systemctl stop safeclaw.service", "systemctl start safeclaw.service"],
        "what step 3 stopped is started again"
    );
    assert!(serve_must_wait(&h.home));
}

#[test]
fn a_sprott_dir_made_by_hand_refuses_and_changes_nothing() {
    let h = Home::new("u");
    seed_15(&h);
    put(&h.new_dir().join("config.toml"), "vault = \"other\"\n");
    let before = snapshot(&h.home);
    let sys = FakeSys::running();
    match run(&h.ctx(&sys, Platform::Systemd)) {
        Err(Fail::Refused(msg)) => assert_eq!(
            msg,
            "Sprott 2.0 could not move ~/.safeclaw: ~/.sprott already exists and did not come from it.\n\
             Fix: move ~/.sprott aside, then run: sprott up"
        ),
        other => panic!("{other:?}"),
    }
    let mut after = snapshot(&h.home);
    after.remove(LOCK);
    assert_eq!(after, before);
    assert!(sys.calls().is_empty());
    assert!(serve_must_wait(&h.home));
}

// ── kills and resumes ────────────────────────────────────────────────────────

fn seeded(name: &str) -> Home {
    let h = Home::new(name);
    seed_15(&h);
    seed_unit(&h, &old_unit_text(&h), true);
    h
}

#[test]
fn a_kill_at_any_step_is_finished_by_the_next_command() {
    let reference = seeded("Mia Li");
    let sys = FakeSys::running();
    moved(run(&reference.ctx(&sys, Platform::Systemd)));
    let want = normalized(&reference);

    for step in [
        Step::Stopped,
        Step::Moved,
        Step::AgentEnv,
        Step::Status,
        Step::UnitWritten,
        Step::Service,
        Step::Started,
        Step::RecordWritten,
    ] {
        let h = seeded("Mia Li");
        let sys = FakeSys::running();
        let mut ctx = h.ctx(&sys, Platform::Systemd);
        ctx.crash_after = Some(step);
        assert!(matches!(run(&ctx), Err(Fail::Crashed)), "{step:?}");

        // Before the rename `serve` waits; after it, `serve` serves.
        let expect = if step == Step::Stopped { State::A } else { State::B };
        assert_eq!(detect(&h.home), expect, "{step:?}");
        assert_eq!(serve_must_wait(&h.home), step == Step::Stopped, "{step:?}");

        ctx.crash_after = None;
        moved(run(&ctx));
        assert_eq!(normalized(&h), want, "{step:?}: same end state as an uninterrupted move");
        assert_eq!(
            sys.count("systemctl start sprott.service"),
            1,
            "{step:?}: the daemon is started once"
        );
        assert!(sys.new_running(), "{step:?}");
    }
}

#[test]
fn the_old_unit_serving_after_a_crash_is_swapped_in_one_bounce() {
    // Killed right after the rename; the old unit then restarted `sc serve`,
    // which is 2.0 now and serves from ~/.sprott (state B).
    let h = seeded("u");
    let sys = FakeSys::running();
    let mut ctx = h.ctx(&sys, Platform::Systemd);
    ctx.crash_after = Some(Step::Moved);
    assert!(matches!(run(&ctx), Err(Fail::Crashed)));
    sys.0.lock().unwrap().old_running = true;
    ctx.crash_after = None;
    moved(run(&ctx));
    let calls = sys.calls();
    let disable = calls.iter().position(|c| c == "systemctl disable --now safeclaw.service");
    let start = calls.iter().position(|c| c == "systemctl start sprott.service");
    assert!(disable.is_some() && start > disable, "{calls:?}");
}

#[cfg(unix)]
#[test]
fn a_read_only_unit_dir_fails_phase_2_and_the_next_command_finishes() {
    use std::os::unix::fs::PermissionsExt;
    let h = seeded("u");
    let sys = FakeSys::running();
    fs::set_permissions(&h.unit_dir, fs::Permissions::from_mode(0o555)).unwrap();
    let ctx = h.ctx(&sys, Platform::Systemd);
    match run(&ctx) {
        Ok(Outcome::Unfinished(e)) => assert!(e.contains("sprott.service"), "{e}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(detect(&h.home), State::B);
    assert!(!serve_must_wait(&h.home));
    fs::set_permissions(&h.unit_dir, fs::Permissions::from_mode(0o755)).unwrap();
    let report = moved(run(&ctx));
    assert_eq!(report.service, Some(Platform::Systemd));
    assert_eq!(sys.count("systemctl start sprott.service"), 1);
}

#[test]
fn two_commands_at_once_move_once() {
    let h = seeded("u");
    let sys = FakeSys::running();
    let outcomes: Vec<Outcome> = std::thread::scope(|s| {
        let a = s.spawn(|| run(&h.ctx(&sys, Platform::Systemd)).unwrap());
        let b = s.spawn(|| run(&h.ctx(&sys, Platform::Systemd)).unwrap());
        vec![a.join().unwrap(), b.join().unwrap()]
    });
    assert_eq!(
        outcomes.iter().filter(|o| matches!(o, Outcome::Moved(_))).count(),
        1,
        "{outcomes:?}"
    );
    assert_eq!(sys.count("systemctl stop safeclaw.service"), 1);
    assert_eq!(sys.count("systemctl start sprott.service"), 1);
}

// ── other managers ───────────────────────────────────────────────────────────

#[test]
fn up_restart_and_down_start_the_daemon_themselves() {
    let h = seeded("u");
    let sys = FakeSys::running();
    let mut ctx = h.ctx(&sys, Platform::Systemd);
    ctx.start_daemon = false;
    moved(run(&ctx));
    assert_eq!(sys.count("systemctl start sprott.service"), 0);
    assert_eq!(sys.count("systemctl enable sprott.service"), 1);
}

#[test]
fn a_stopped_daemon_with_a_disabled_unit_stays_stopped_and_disabled() {
    let h = Home::new("u");
    seed_15(&h);
    seed_unit(&h, &old_unit_text(&h), false);
    let sys = FakeSys::default();
    let report = moved(run(&h.ctx(&sys, Platform::Systemd)));
    assert_eq!(report.service, Some(Platform::Systemd));
    assert_eq!(
        sys.calls(),
        [
            "systemctl stop safeclaw.service",
            "systemctl disable --now safeclaw.service",
            "systemctl daemon-reload",
        ]
    );
}

#[test]
fn a_detached_daemon_is_stopped_by_its_pid_and_started_detached() {
    let h = Home::new("u");
    seed_15(&h);
    put(&h.old().join("daemon.pid"), "4242\n");
    let sys = FakeSys::running();
    sys.0.lock().unwrap().detached_pid = Some(4242);
    let report = moved(run(&h.ctx(&sys, Platform::Systemd)));
    assert_eq!(report_lines(&report), ["Moved ~/.safeclaw to ~/.sprott."]);
    assert_eq!(sys.calls(), ["kill 4242", "spawn /opt/sprott/bin/sprott serve"]);
    assert_eq!(read(&h.new_dir().join("daemon.pid")), "4242\n");
}

#[test]
fn a_hand_written_unit_is_left_and_reported() {
    let h = Home::new("u");
    seed_15(&h);
    let unit = "[Service]\nExecStart=/usr/local/bin/sc serve\n";
    seed_unit(&h, unit, true);
    let sys = FakeSys::running();
    let report = moved(run(&h.ctx(&sys, Platform::Systemd)));
    assert_eq!(report.service, None);
    assert_eq!(
        report.left,
        ["~/.config/systemd/user/safeclaw.service was not generated by sprott; it was left as it is."]
    );
    assert_eq!(read(&h.unit_dir.join(OLD_UNIT)), unit);
    assert!(!h.unit_dir.join("sprott.service").exists());
    assert_eq!(
        sys.calls(),
        ["systemctl stop safeclaw.service", "systemctl start safeclaw.service"]
    );
    assert!(findings(&h.home, &h.unit_dir, &h.agents).iter().any(|f| f
        .starts_with("~/.config/systemd/user/safeclaw.service is a service file from before 2.0")));
}

#[test]
fn a_launchd_install_moves_to_ai_sprott_daemon() {
    let h = Home::new("Mia Li");
    seed_15(&h);
    let home = h.h();
    let old_plist = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!-- Generated by safeclaw. Do not edit; re-run `sprott up` to refresh. -->\n\
         <plist version=\"1.0\">\n<dict>\n  <key>Label</key>\n  <string>pro.safeclaw.daemon</string>\n\
         \x20 <key>ProgramArguments</key>\n  <array>\n    <string>{home}/.local/bin/sc</string>\n    <string>serve</string>\n  </array>\n\
         \x20 <key>EnvironmentVariables</key>\n  <dict>\n\
         \x20   <key>SAFECLAW_PORT</key><string>24000</string>\n\
         \x20   <key>SAFECLAW_CA_PATH</key><string>{home}/.safeclaw/state/ca&amp;.pem</string>\n  </dict>\n\
         \x20 <key>StandardOutPath</key>\n  <string>{home}/.safeclaw/daemon.log</string>\n</dict>\n</plist>\n"
    );
    put(&h.agents.join("pro.safeclaw.daemon.plist"), &old_plist);
    let sys = FakeSys::running();

    let report = moved(run(&h.ctx(&sys, Platform::Launchd)));
    assert_eq!(
        report_lines(&report),
        ["Moved ~/.safeclaw to ~/.sprott; the daemon is now ai.sprott.daemon."]
    );
    assert_eq!(
        read(&h.agents.join("ai.sprott.daemon.plist")),
        crate::cli::service::launchd_plist(
            "ai.sprott.daemon",
            "/opt/sprott/bin/sprott",
            &[
                ("SPROTT_PORT".to_string(), "24000".to_string()),
                ("SPROTT_CA_PATH".to_string(), format!("{home}/.sprott/state/ca&.pem")),
            ],
            &format!("{home}/.sprott/daemon.log"),
        )
    );
    assert!(!h.agents.join("pro.safeclaw.daemon.plist").exists());
    assert_eq!(read(&h.new_dir().join(PRE_2).join("pro.safeclaw.daemon.plist")), old_plist);
    let new_plist = h.agents.join("ai.sprott.daemon.plist").display().to_string();
    assert_eq!(
        sys.calls(),
        [
            "launchctl bootout gui/501/pro.safeclaw.daemon".to_string(),
            "launchctl bootout gui/501/pro.safeclaw.daemon".to_string(),
            "launchctl bootout gui/501/ai.sprott.daemon".to_string(),
            "launchctl enable gui/501/ai.sprott.daemon".to_string(),
            format!("launchctl bootstrap gui/501 {new_plist}"),
            "launchctl kickstart -k gui/501/ai.sprott.daemon".to_string(),
        ]
    );
}

// ── small parts ──────────────────────────────────────────────────────────────

#[test]
fn the_control_port_comes_from_the_old_config() {
    let h = Home::new("u");
    let dir = h.old();
    assert_eq!(control_authority(&dir), "127.0.0.1:23293");
    put(&dir.join("config.toml"), "daemon = \"http://127.0.0.1:24000\"\n");
    assert_eq!(control_authority(&dir), "127.0.0.1:24000");
    put(&dir.join("config.toml"), "custodian = \"http://localhost:24001/\"\n");
    assert_eq!(control_authority(&dir), "localhost:24001");
    put(&dir.join("config.toml"), "daemon = \"https://vault.example.com\"\n");
    assert_eq!(control_authority(&dir), "127.0.0.1:23293", "only a local daemon is ours to stop");
}

#[test]
fn a_finished_move_with_a_recreated_old_dir_is_reported_not_read() {
    let h = seeded("u");
    let sys = FakeSys::running();
    moved(run(&h.ctx(&sys, Platform::Systemd)));
    fs::create_dir(h.old()).unwrap();
    assert_eq!(detect(&h.home), State::C);
    assert_eq!(run(&h.ctx(&sys, Platform::Systemd)).unwrap(), Outcome::Nothing);
    assert!(findings(&h.home, &h.unit_dir, &h.agents)
        .iter()
        .any(|f| f.starts_with("~/.safeclaw exists again beside ~/.sprott")));
}
