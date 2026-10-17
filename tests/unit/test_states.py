from siemsoar.states import TERMINAL, TRANSITIONS, Status, is_terminal, sources_for


def test_terminal_states_match_proposal():
    assert TERMINAL == {Status.RESTORED, Status.DISMISSED, Status.EXPIRED, Status.ACKNOWLEDGED, Status.FAILED}


def test_every_non_initial_state_is_reachable_from_new():
    seen, stack = set(), [Status.NEW]
    while stack:
        s = stack.pop()
        if s not in seen:
            seen.add(s)
            stack.extend(TRANSITIONS[s])
    assert seen == set(Status)


def test_sources_for_notified_and_isolating():
    assert sources_for(Status.NOTIFIED) == [Status.NEW]
    assert set(sources_for(Status.ISOLATING)) == {Status.APPROVED}
    assert Status.ISOLATED not in sources_for(Status.APPROVED)


def test_terminal_cannot_transition():
    assert all(is_terminal(s.value) for s in TERMINAL)
    assert all(not TRANSITIONS[s] for s in TERMINAL)
