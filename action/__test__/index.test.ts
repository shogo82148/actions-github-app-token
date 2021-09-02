import * as os from 'os';
import {promises as fs} from 'fs';
import * as path from 'path';
import * as child_process from 'child_process';
import * as core from '@actions/core';
import * as io from '@actions/io';
import * as exec from '@actions/exec';
import * as index from '../src/index';

// The environment values defined in the GitHub Actions Environment
// https://docs.github.com/en/actions/reference/environment-variables#default-environment-variables
process.env.GITHUB_REPOSITORY = 'shogo82148/actions-aws-assume-role';
process.env.GITHUB_WORKFLOW = 'test';
process.env.GITHUB_RUN_ID = '1234567890';
process.env.GITHUB_ACTOR = 'shogo82148';
process.env.GITHUB_SHA = 'e3a45c6c16c1464826b36a598ff39e6cc98c4da4';
process.env.GITHUB_REF = 'ref/heads/main';

const sep = path.sep;

// extension of executable files
const binExt = os.platform() === 'win32' ? '.exe' : '';

jest.mock('@actions/core');

describe('tests', () => {
  let tmpdir = '';
  let subprocess: child_process.ChildProcess;

  // compile and start the dummy API server.
  beforeAll(async () => {
    tmpdir = await fs.mkdtemp(`${os.tmpdir}${sep}actions-github-app-token-`);
    const bin = `${tmpdir}${sep}dummy${binExt}`;

    console.log('compiling dummy server');
    await exec.exec(
      'go',
      ['build', '-o', bin, 'github.com/shogo82148/actions-github-app-token/provider/github-app-token/cmd/dummy'],
      {
        cwd: `..${sep}provider${sep}github-app-token`
      }
    );

    console.log('starting dummy server');
    subprocess = child_process.spawn(bin, [], {
      detached: true,
      stdio: 'ignore'
    });
    await sleep(1); // wait for starting process
  }, 5 * 60000);

  afterAll(async () => {
    console.log('killing dummy server');
    subprocess?.kill('SIGTERM');
    try {
      await sleep(1); // wait for stopping process
      await io.rmRF(tmpdir);
    } catch (error) {
      // suppress the error
      core.info(`[warning]: ${error}`);
    }
  });

  it('succeed', async () => {
    await index.assumeRole({
      githubToken: 'ghs_dummyGitHubToken',
      providerEndpoint: 'http://localhost:8080'
    });
    expect(core.setSecret).toHaveBeenCalledWith('FIXME!!!');
  });
});

function sleep(waitSec: number): Promise<void> {
  return new Promise<void>(function (resolve) {
    setTimeout(() => resolve(), waitSec * 1000);
  });
}
