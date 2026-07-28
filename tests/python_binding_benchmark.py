import json, os, statistics, sys, tempfile, time
sys.path.insert(0, sys.argv[1])
import _soci

warmup = int(os.getenv("BINDING_WARMUP", "5"))
samples = int(os.getenv("BINDING_SAMPLES", "20"))
metrics = []
with tempfile.TemporaryDirectory() as d:
    r = _soci.SociRuntime(d)
    r.create_key("binding", 3072)
    a, b = r.encrypt("12345"), r.encrypt("-67")
    cases = [
        ("Encrypt", lambda: r.encrypt("12345"), None),
        ("Decrypt", lambda: r.decrypt(a), "12345"),
        ("SADD", lambda: r.add(a,b), "12278"),
        ("ScalarMul", lambda: r.scalar_mul(a,"19"), str(12345*19)),
        ("SMUL", lambda: r.secure_mul(a,b), str(12345*-67)),
        ("SCMP", lambda: r.secure_compare(a,b), "1"),
        ("SABS", lambda: r.secure_abs(b), "67"),
    ]
    for name, fn, expected in cases:
        values=[]; ok=True
        for i in range(warmup+samples):
            t=time.perf_counter_ns(); out=fn(); elapsed=(time.perf_counter_ns()-t)/1000
            if i>=warmup: values.append(elapsed)
        if expected is not None: ok=(out==expected if name=="Decrypt" else r.decrypt(out)==expected)
        values.sort()
        metrics.append({"operation":name,"samples":samples,"mean_us":statistics.mean(values),
                        "p50_us":values[(len(values)-1)//2],"p95_us":values[max(0,int(.95*len(values)+.999999)-1)],
                        "correct":ok})
    t=time.perf_counter_ns(); div=r.secure_div(a,r.encrypt("100")); elapsed=(time.perf_counter_ns()-t)/1000
    metrics.append({"operation":"SDIV","samples":1,"mean_us":elapsed,"p50_us":elapsed,
                    "p95_us":elapsed,"correct":r.decrypt(div.quotient)=="123" and r.decrypt(div.remainder)=="45"})
print(json.dumps({"binding":"Python/pybind11","security_bits":128,"warmup":warmup,"metrics":metrics},indent=2))
