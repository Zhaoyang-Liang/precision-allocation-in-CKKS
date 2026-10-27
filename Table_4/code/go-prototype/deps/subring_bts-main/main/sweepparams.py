import subprocess
import re
import numpy as np
import os

logPfailRange = [-16, -32, -64, -128] # full loop
scaleRange = [30, 35, 40, 45] # full
doubleAngleRange = [2, 3, 4] # full
degreeRange = [255, 127, 63] # full
qiBiasRange = [3, 5, 7, 9, 10, 11, 12] # abort at first prec loss
precLossThres = 0.1
repeat=5

def parse_results(results):
    L1err = re.search(r"Avg L1 error is ([\d\-\.]+)", results)
    Levels = re.search(r"Number of circuit primes = (\d+)", results)
    logPfail = re.search(r"Failure prob is 2\^([\d\-\.]+)", results)
    logQP = re.search(r"logQP=([\d\.]+)", results)
    times = re.findall(r"StC: ([\d\.]+)s, ModUp: ([\d\.]+)ms, CtS: ([\d\.]+)s, EvalMod: ([\d\.]+)s", results)
    if None in [L1err, Levels, logPfail, logQP, times]:
        print("cannot parse result")
        return
    L1err = float(L1err.groups()[0])
    Levels = int(Levels.groups()[0])
    logPfail = float(logPfail.groups()[0])
    logQP = float(logQP.groups()[0])
    times = np.array(times, dtype=float)
    times = np.mean(times, 0)
    # print(times, np.sum(times) - times[1])
    # exit(1)
    times = np.hstack([np.sum(times) - times[1], times])
    return L1err, Levels, logPfail, logQP, list(times)


def run_program(args):
    try:
        # Run the executable with arguments and capture stdout
        result = subprocess.run(
            ["/opt/go/bin/go", "run", "main"] + args,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True  # This ensures output is returned as a string instead of bytes
        )

    except subprocess.CalledProcessError as e:
        # If the executable returns a non-zero exit code, it will raise CalledProcessError
        print(f"Error occurred: {e} for args {args}")
        print("Standard Error:")
        print(e.stderr)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    return result.stdout

def run_and_get_prec(paramMap):
    args = [f"-{k}={v}" for k,v in paramMap.items()]
    res = run_program(args + [f"-repeat={repeat}"])
    with open("../logs/"+"_".join([f"{k}={v}" for k,v in sorted(paramMap.items())]) + ".log", "w") as f:
        f.write(res)
    return parse_results(res)

def sweep():
    for logPfail in logPfailRange:
        for scale in scaleRange:
            for doubleAngle in doubleAngleRange:
                for degree in degreeRange:
                    paramMap = {"eps": logPfail, "scale": scale, "r": doubleAngle, "degree": degree, 
                                "scalestc": scale, "scalects": 60}
                    # full loops
                    BaseL1err, _, _, _, _ = run_and_get_prec(paramMap)
                    if BaseL1err < 0:
                        break
                    # StC
                    prevBias = 0
                    for curBias in qiBiasRange:
                        paramMap['scalestc'] = scale - curBias
                        curL1err, _, _, _, _ = run_and_get_prec(paramMap)
                        if curL1err < BaseL1err - precLossThres:
                            for subBias in range(prevBias + 1, curBias):
                                paramMap['scalestc'] = scale - subBias
                                subL1err, _, _, _, _ = run_and_get_prec(paramMap)
                                if subL1err < BaseL1err - precLossThres:
                                    paramMap['scalestc'] = scale - prevBias
                                    break
                                prevBias = subBias
                            break
                        prevBias = curBias
                    # CtS
                    prevBias = 0
                    for curBias in qiBiasRange:
                        paramMap['scalects'] = 60 - curBias
                        curL1err, _, _, _, _ = run_and_get_prec(paramMap)
                        if curL1err < BaseL1err - precLossThres:
                            for subBias in range(prevBias + 1, curBias):
                                paramMap['scalects'] = 60 - subBias
                                subL1err, _, _, _, _ = run_and_get_prec(paramMap)
                                if subL1err < BaseL1err - precLossThres:
                                    paramMap['scalects'] = 60 - prevBias
                                    break
                                prevBias = subBias
                            break
                        prevBias = curBias


if __name__ == "__main__":
    files = os.listdir("../logs")
    eps_dict = {-16: [], -32: [], -64: [], -128:[]}
    for file in files:
        deg, eps, r, scale, scalects, scalestc = [int(_) for _ in 
            re.search(r"degree=(\d+)_eps=([\-\d]+)_r=(\d)_scale=(\d+)_scalects=(\d+)_scalestc=(\d+)", file).groups(0)]
        with open(f"../logs/{file}") as f:
            parsed = parse_results(f.read())
        eps_dict[eps].append([deg, r, scale, scalects, scalestc] + list(parsed))
    for eps in [-16, -32, -64, -128]:
        for _ in eps_dict[eps]:
            print(eps, _)
        print("########\n#######")