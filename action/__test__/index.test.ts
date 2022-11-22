import * as os from "os";
import { promises as fs } from "fs";
import * as path from "path";
import * as child_process from "child_process";
import * as core from "@actions/core";
import * as io from "@actions/io";
import * as exec from "@actions/exec";
import * as index from "../src/index";

const sep = path.sep;

// extension of executable files
const binExt = os.platform() === "win32" ? ".exe" : "";

jest.mock("@actions/core");

describe("tests", () => {
  let tmpdir = "";
  let subprocess: child_process.ChildProcess;

  // compile and start the dummy API server.
  beforeAll(async () => {
    tmpdir = await fs.mkdtemp(`${os.tmpdir}${sep}actions-github-app-token-`);
    const bin = `${tmpdir}${sep}dummy${binExt}`;

    console.log("compiling dummy server");
    await exec.exec(
      "go",
      ["build", "-o", bin, "github.com/shogo82148/actions-github-app-token/provider/github-app-token/cmd/dummy"],
      {
        cwd: `..${sep}provider${sep}github-app-token`,
      }
    );

    console.log("starting dummy server");
    subprocess = child_process.spawn(bin, [], {
      detached: true,
      stdio: "ignore",
    });
    await sleep(1); // wait for starting process
  }, 5 * 60000);

  afterAll(async () => {
    console.log("killing dummy server");
    subprocess?.kill("SIGTERM");
    try {
      await sleep(1); // wait for stopping process
      await io.rmRF(tmpdir);
    } catch (error) {
      // suppress the error
      core.info(`[warning]: ${error}`);
    }
  });

  it("succeed", async () => {
    await index.assumeRole({
      providerEndpoint: "http://localhost:8080",
      audience: "https://github-app.shogo82148.com/1234567890",
      repositories: ["R_123456"],
    });
    expect(core.setSecret).toHaveBeenCalledWith("ghs_dummyGitHubToken");
  });
});

function sleep(waitSec: number): Promise<void> {
  return new Promise<void>(function (resolve) {
    setTimeout(() => resolve(), waitSec * 1000);
  });
}
