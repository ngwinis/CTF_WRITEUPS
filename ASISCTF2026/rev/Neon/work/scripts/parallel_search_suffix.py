import argparse
import hashlib
import multiprocessing as mp
import time

from search_suffix import generate_suffixes, parse_allowed
from solve_neon import ACTION_NAMES, FIRST16, NeonHarness, REPLAY_OUT, STAGE2_OUT, make_replay


def worker_main(
    worker_id: int,
    worker_count: int,
    allowed_text: str,
    prefix_text: str,
    max_nonmove: int | None,
    no_revisit: bool,
    no_backtrack: bool,
    start_index: int,
    stop_index: int,
    progress: int,
    stop_event,
    queue,
):
    allowed = parse_allowed(allowed_text)
    required_prefix = parse_allowed(prefix_text) if prefix_text else []
    harness = NeonHarness()
    base_actions = FIRST16 + [5] * 15 + [11]
    snap = harness.run_to_row_start(base_actions, 16)
    checked = 0
    started = time.time()

    for index, suffix in enumerate(
        generate_suffixes(allowed, max_nonmove, no_revisit, no_backtrack)
    ):
        if required_prefix and suffix[: len(required_prefix)] != required_prefix:
            continue
        if index < start_index:
            continue
        if stop_index and index >= stop_index:
            break
        if stop_event.is_set():
            break
        if index % worker_count != worker_id:
            continue

        reason, aes_ok, rows, out = harness.run_suffix_from_snapshot(snap, suffix)
        checked += 1

        if aes_ok or out[0] == 1:
            actions = FIRST16 + suffix + [11]
            queue.put(
                {
                    "type": "found",
                    "worker": worker_id,
                    "checked": checked,
                    "global_index": index,
                    "suffix": suffix,
                    "actions": actions,
                    "reason": reason,
                    "aes_ok": aes_ok,
                    "rows": rows,
                    "out": out.hex(),
                    "stage2": harness.last_stage2.hex() if harness.last_stage2 else "",
                }
            )
            stop_event.set()
            return

        if progress and checked % progress == 0:
            queue.put(
                {
                    "type": "progress",
                    "worker": worker_id,
                    "checked": checked,
                    "global_index": index,
                    "elapsed": round(time.time() - started, 1),
                    "reason": reason,
                    "rows": rows,
                }
            )

    queue.put(
        {
            "type": "done",
            "worker": worker_id,
            "checked": checked,
            "elapsed": round(time.time() - started, 1),
        }
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--allowed", default="W S A D X")
    parser.add_argument("--prefix", default="")
    parser.add_argument("--max-nonmove", type=int)
    parser.add_argument("--no-revisit", action="store_true")
    parser.add_argument("--no-backtrack", action="store_true")
    parser.add_argument("--workers", type=int, default=max(1, min(8, mp.cpu_count())))
    parser.add_argument("--start-index", type=int, default=0)
    parser.add_argument("--stop-index", type=int, default=0)
    parser.add_argument("--progress", type=int, default=250)
    args = parser.parse_args()

    worker_count = max(1, args.workers)
    stop_event = mp.Event()
    queue = mp.Queue()
    workers = [
        mp.Process(
            target=worker_main,
            args=(
                worker_id,
                worker_count,
                args.allowed,
                args.prefix,
                args.max_nonmove,
                args.no_revisit,
                args.no_backtrack,
                args.start_index,
                args.stop_index,
                args.progress,
                stop_event,
                queue,
            ),
        )
        for worker_id in range(worker_count)
    ]

    for proc in workers:
        proc.start()

    done = 0
    try:
        while done < worker_count:
            msg = queue.get()
            if msg["type"] == "progress":
                print(
                    "progress",
                    f"worker={msg['worker']}",
                    f"checked={msg['checked']}",
                    f"global={msg['global_index']}",
                    f"elapsed={msg['elapsed']}",
                    f"reason={msg['reason']}",
                    f"rows={msg['rows']}",
                    flush=True,
                )
            elif msg["type"] == "done":
                done += 1
                print(
                    "done",
                    f"worker={msg['worker']}",
                    f"checked={msg['checked']}",
                    f"elapsed={msg['elapsed']}",
                    flush=True,
                )
            elif msg["type"] == "found":
                stop_event.set()
                actions = msg["actions"]
                replay = make_replay(actions)
                REPLAY_OUT.write_bytes(replay)
                if msg["stage2"]:
                    stage2 = bytes.fromhex(msg["stage2"])
                    STAGE2_OUT.write_bytes(stage2)
                    print("stage2_sha256:", hashlib.sha256(stage2).hexdigest(), flush=True)
                print("FOUND", flush=True)
                print("worker:", msg["worker"], "global_index:", msg["global_index"], flush=True)
                print("suffix:", msg["suffix"], flush=True)
                print("keys:", " ".join(ACTION_NAMES[a] for a in actions), flush=True)
                print(
                    "reason:",
                    msg["reason"],
                    "aes_ok:",
                    msg["aes_ok"],
                    "rows:",
                    msg["rows"],
                    flush=True,
                )
                print("out:", msg["out"], flush=True)
                print("replay:", REPLAY_OUT, flush=True)
                return
    finally:
        stop_event.set()
        for proc in workers:
            proc.join(timeout=1)
            if proc.is_alive():
                proc.terminate()
                proc.join()


if __name__ == "__main__":
    main()
