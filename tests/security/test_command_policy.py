from sentinel.core.security.command_policy import CommandPolicy, CommandRule


def test_command_allowlisted_allowed():
    policy = CommandPolicy([CommandRule("python", ("-m",), True)])
    dec = policy.validate(["python", "-m", "sentinel"])
    assert dec.allowed is True

def test_command_unallowlisted_executable_blocked():
    policy = CommandPolicy([CommandRule("python", (), True)])
    dec = policy.validate(["bash", "-c", "whoami"])
    assert dec.allowed is False
    assert "not allowlisted" in dec.reason

def test_command_unallowlisted_subcommand_blocked():
    policy = CommandPolicy([CommandRule("git", ("status", "diff"), True)])
    dec = policy.validate(["git", "push", "origin", "main"])
    assert dec.allowed is False
    assert "Subcommand denied" in dec.reason

def test_command_shell_metacharacters_rejected():
    policy = CommandPolicy([CommandRule("python", (), True)])
    for meta in [";", "&&", "||", "|", ">", ">>", "<", "$(", "`"]:
        dec = policy.validate(["python", f"script.py{meta}evil"])
        assert dec.allowed is False
        assert "Shell metacharacters are forbidden" in dec.reason
