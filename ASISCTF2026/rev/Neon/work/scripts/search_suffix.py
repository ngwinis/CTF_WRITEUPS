import argparse
import hashlib

from solve_neon import (
    ACTION_NAMES,
    FIRST16,
    NeonHarness,
    REPLAY_OUT,
    STAGE2_OUT,
    make_replay,
)


VAULT_MAP = [
    "  ..                ",
    "  ...               ",
    "  @W..       .      ",
    "  .....    .....    ",
    "  ........#....>..  ",
    "  ......K.#.......  ",
    "  ........#.......  ",
    "  ........#.......  ",
    "  ........#.......  ",
    "   .......#.......  ",
    "   .......##......  ",
    "    .......##.....  ",
    "     .......##..... ",
    "      .......#..... ",
    "        .....D......",
    "                 .....",
]

START = (7, 4)
TARGET = (8, 5)
MOVES = {1: (0, -1), 2: (0, 1), 3: (-1, 0), 4: (1, 0)}


def passable(x: int, y: int) -> bool:
    if y < 0 or y >= len(VAULT_MAP):
        return False
    if x < 0 or x >= len(VAULT_MAP[y]):
        return False
    return VAULT_MAP[y][x] not in " #"


def parse_allowed(text: str) -> list[int]:
    by_key = {v: k for k, v in ACTION_NAMES.items()}
    out = []
    for tok in text.replace(",", " ").split():
        up = tok.upper()
        if up in by_key:
            out.append(by_key[up])
        else:
            out.append(int(up))
    return out


REVERSE = {1: 2, 2: 1, 3: 4, 4: 3}


def can_still_reach(
    pos: tuple[int, int],
    depth: int,
    nonmove: int,
    allowed: list[int],
    max_nonmove: int | None,
) -> bool:
    remaining = 15 - depth
    distance = abs(pos[0] - TARGET[0]) + abs(pos[1] - TARGET[1])
    if distance > remaining:
        return False

    has_nonmove = any(action not in MOVES for action in allowed)
    if max_nonmove is None:
        if has_nonmove:
            return True
        return distance % 2 == remaining % 2

    if nonmove > max_nonmove:
        return False
    max_extra_nonmove = min(max_nonmove - nonmove, remaining) if has_nonmove else 0
    for extra_nonmove in range(max_extra_nonmove + 1):
        move_steps = remaining - extra_nonmove
        if distance <= move_steps and distance % 2 == move_steps % 2:
            return True
    return False


def generate_suffixes(
    allowed: list[int],
    max_nonmove: int | None,
    no_revisit: bool,
    no_backtrack: bool,
):
    suffix: list[int] = []
    visited = {START}

    def dfs(pos: tuple[int, int], depth: int, nonmove: int, last_move: int | None):
        if not can_still_reach(pos, depth, nonmove, allowed, max_nonmove):
            return
        if depth == 15:
            if pos == TARGET:
                yield list(suffix)
            return
        for action in allowed:
            if action in MOVES:
                if no_backtrack and last_move is not None and action == REVERSE.get(last_move):
                    continue
                dx, dy = MOVES[action]
                nxt = (pos[0] + dx, pos[1] + dy)
                if not passable(*nxt):
                    continue
                if no_revisit and nxt in visited:
                    continue
                extra_nonmove = 0
                next_last_move = action
            else:
                nxt = pos
                extra_nonmove = 1
                next_last_move = last_move
            suffix.append(action)
            if action in MOVES and no_revisit:
                visited.add(nxt)
            yield from dfs(nxt, depth + 1, nonmove + extra_nonmove, next_last_move)
            if action in MOVES and no_revisit:
                visited.remove(nxt)
            suffix.pop()

    yield from dfs(START, 0, 0, None)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--allowed", default="W S A D X")
    parser.add_argument("--max-nonmove", type=int)
    parser.add_argument("--count-only", action="store_true")
    parser.add_argument("--no-revisit", action="store_true")
    parser.add_argument("--no-backtrack", action="store_true")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--progress", type=int, default=100)
    parser.add_argument("--incremental", action="store_true")
    parser.add_argument("--frontier-limit", type=int, default=20000)
    args = parser.parse_args()

    allowed = parse_allowed(args.allowed)
    checked = 0

    if args.count_only:
        for _ in generate_suffixes(allowed, args.max_nonmove, args.no_revisit, args.no_backtrack):
            checked += 1
        print("count:", checked)
        return

    harness = NeonHarness()
    base_actions = FIRST16 + [5] * 15 + [11]
    snap = harness.run_to_row_start(base_actions, 16)
    print(
        f"base snapshot: heap={snap.heap_cur:#x} stack_copy={len(snap.stack)} "
        f"allowed={' '.join(ACTION_NAMES[a] for a in allowed)}"
    )
    if args.incremental:
        frontier = [(START, 0, None, frozenset([START]), [], snap)]
        for index in range(16, 31):
            next_frontier = []
            for pos, nonmove, last_move, visited, prefix, cur_snap in frontier:
                for action in allowed:
                    if action in MOVES:
                        if args.no_backtrack and last_move is not None and action == REVERSE.get(last_move):
                            continue
                        dx, dy = MOVES[action]
                        nxt = (pos[0] + dx, pos[1] + dy)
                        if not passable(*nxt):
                            continue
                        if args.no_revisit and nxt in visited:
                            continue
                        new_nonmove = nonmove
                        new_last = action
                        new_visited = visited | {nxt} if args.no_revisit else visited
                    else:
                        nxt = pos
                        new_nonmove = nonmove + 1
                        new_last = last_move
                        new_visited = visited
                    if not can_still_reach(
                        nxt, index - 15, new_nonmove, allowed, args.max_nonmove
                    ):
                        continue
                    child = harness.run_from_snapshot_to_row(cur_snap, index, action)
                    if child is not None:
                        next_frontier.append(
                            (nxt, new_nonmove, new_last, new_visited, prefix + [action], child)
                        )
            print(f"row {index}: {len(frontier)} -> {len(next_frontier)}")
            if not next_frontier:
                print("no survivors")
                return
            if len(next_frontier) > args.frontier_limit:
                print("frontier limit exceeded:", len(next_frontier))
                return
            frontier = next_frontier
        for pos, _nonmove, _last, _visited, suffix, cur_snap in frontier:
            if pos != TARGET:
                continue
            reason, aes_ok, rows, out = harness.finish_from_snapshot(cur_snap)
            checked += 1
            if aes_ok or out[0] == 1:
                actions = FIRST16 + suffix + [11]
                print("FOUND")
                print("suffix:", suffix)
                print("keys:", " ".join(ACTION_NAMES[a] for a in actions))
                print("reason:", reason, "aes_ok:", aes_ok, "rows:", rows)
                print("out:", out.hex())
                if harness.last_stage2:
                    STAGE2_OUT.write_bytes(harness.last_stage2)
                    print("stage2_sha256:", hashlib.sha256(harness.last_stage2).hexdigest())
                replay = make_replay(actions)
                REPLAY_OUT.write_bytes(replay)
                print("replay:", REPLAY_OUT)
                print("checked finals:", checked)
                return
            if args.progress and checked % args.progress == 0:
                print("checked finals:", checked, "last_reason:", reason, "rows:", rows)
        print("done finals:", checked)
        return

    for suffix in generate_suffixes(allowed, args.max_nonmove, args.no_revisit, args.no_backtrack):
        checked += 1
        reason, aes_ok, rows, out = harness.run_suffix_from_snapshot(snap, suffix)
        if aes_ok or out[0] == 1:
            actions = FIRST16 + suffix + [11]
            print("FOUND")
            print("suffix:", suffix)
            print("keys:", " ".join(ACTION_NAMES[a] for a in actions))
            print("reason:", reason, "aes_ok:", aes_ok, "rows:", rows)
            print("out:", out.hex())
            if harness.last_stage2:
                STAGE2_OUT.write_bytes(harness.last_stage2)
                print("stage2_sha256:", hashlib.sha256(harness.last_stage2).hexdigest())
            replay = make_replay(actions)
            REPLAY_OUT.write_bytes(replay)
            print("replay:", REPLAY_OUT)
            print("checked:", checked)
            return
        if args.progress and checked % args.progress == 0:
            print("checked:", checked, "last_reason:", reason, "rows:", rows)
        if args.limit and checked >= args.limit:
            print("limit reached:", checked)
            return
    print("done checked:", checked)


if __name__ == "__main__":
    main()
