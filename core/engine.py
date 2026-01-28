from concurrent.futures import ThreadPoolExecutor

def run_parallel(tasks):
    findings = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        results = executor.map(lambda f: f(), tasks)
        for r in results:
            if r:
                findings.extend(r)
    return findings

