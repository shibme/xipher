const exec = require('@actions/exec');
const os = require('os');
const core = require('@actions/core');
const tc = require('@actions/tool-cache');
const { Octokit } = require("@octokit/rest");
let octokit;
const token = core.getInput('github-token');
const userAgent = 'xipher-action';
if (token) {
  const { createTokenAuth } = "@octokit/auth-token";
  octokit = new Octokit({
    authStrategy: createTokenAuth,
    auth: token,
    userAgent: userAgent,
  });
} else {
  octokit = new Octokit({
    userAgent: userAgent,
  });
}

const owner = 'shibme';
const repo = 'xipher';
const assetName = 'xipher';

async function showVersion() {
  try {
    const options = {
      silent: true,
      failOnStdErr: true
    };
    const execOutput = await exec.getExecOutput('xipher', ['--version'], options);
    core.info(execOutput.stdout);
  } catch (error) {
    core.setFailed('Error executing xipher --version: ' + error.message);
  }
}

async function findInstalledVersion() {
  const options = {
    silent: true,
    failOnStdErr: true
  };
  try {
    const execOutput = await exec.getExecOutput('xipher', ['--version'], options);
    let installedVersion = '';
    const lines = execOutput.stdout.split("\n");
    for (const line of lines) {
      if (line.toLowerCase().includes("version")) {
        installedVersion = line.split(':')[1];
        installedVersion = installedVersion.trim();
        if (installedVersion.startsWith('v')) {
          installedVersion = installedVersion.slice(1);
        }
        break;
      }
    }
    core.saveState('XIPHER_VERSION_INSTALLED', installedVersion);
    return installedVersion;
  } catch (error) {
    return '';
  }
}

async function getInstalledVersion() {
  let installedVersion = core.getState('XIPHER_VERSION_INSTALLED');
  if (installedVersion === undefined || installedVersion === '') {
    installedVersion = await findInstalledVersion();
  }
  if (installedVersion) {
    core.info(`Installed version of Xipher: ${ installedVersion }`);
  }
  return installedVersion;
}

async function getLatestVersion() {
  try {
    let latestVersion = core.getState('XIPHER_VERSION_LATEST');
    if (latestVersion === undefined || latestVersion === '') {
      core.info('Fetching latest release version from GitHub...');
      const latestRelease = await octokit.rest.repos.getLatestRelease({
        owner: owner,
        repo: repo
      });
      latestVersion = latestRelease.data.tag_name;
      if (latestVersion.startsWith('v')) {
        latestVersion = latestVersion.slice(1);
      }
      core.saveState('XIPHER_VERSION_LATEST', latestVersion);
    }
    return latestVersion;
  } catch (error) {
    core.setFailed('Error retrieving latest release version:' + error.message);
  }
}

function mapArch(arch) {
  const mappings = {
    x32: '386',
    x64: 'amd64'
  };
  return mappings[arch] || arch;
}

function mapOS(os) {
  const mappings = {
    win32: 'windows'
  };
  return mappings[os] || os;
}

async function getDownloadUrlForVersion(version) {
  const platform = os.platform();
  try {
    const release = await octokit.rest.repos.getReleaseByTag({
      owner: owner,
      repo: repo,
      tag: `v${ version }`
    });
    const assets = release.data.assets;
    if (assets.length === 0) {
      core.setFailed('No assets found in the release version ' + version);
    }
    for (let i = 0; i < assets.length; i++) {
      if (assets[i].name.includes(assetName + '_') && 
          assets[i].name.includes(mapOS(platform)) && 
          assets[i].name.includes(mapArch(os.arch())) && 
          assets[i].name.includes('.zip')) {
        return assets[i].browser_download_url;
      }
    }
  } catch (error) {
    core.setFailed('Error retrieving download URL for version ' + version + ': ' + error.message);
    return '';
  }
  core.setFailed('No assets found for current the platform (' + mapOS(platform) + 
    '-' + mapArch(os.arch()) + ') in the release version ' + version);
  return '';
}

async function installVersion(version) {
  try {
    const downloadUrl = await getDownloadUrlForVersion(version);
    if (!downloadUrl) {
      return;
    }
    const pathToZip = await tc.downloadTool(downloadUrl);
    const pathToCLI = await tc.extractZip(pathToZip);
    core.addPath(pathToCLI);
    const installed_version = await findInstalledVersion();
    if (installed_version === version) {
      core.info(`Successfully installed Xipher version ${ version }`);
    } else {
      core.setFailed(`Failed to install Xipher version ${ version }`);
    }
  } catch (e) {
    core.setFailed(e);
  }
}

async function setup() {
  try {
    const installedVersion = await getInstalledVersion();
    let requiredVersion = core.getInput('version');
    if (!requiredVersion || requiredVersion === 'latest') {
      requiredVersion = await getLatestVersion();
    } else if (requiredVersion.startsWith('v')) {
      requiredVersion = requiredVersion.slice(1);
    }
    if (installedVersion && installedVersion === requiredVersion) {
      core.info(`Required version Xipher ${ installedVersion } is already installed`);
      return;
    }
    await installVersion(requiredVersion);
  } catch (e) {
    core.setFailed(e);
  }
}

async function run() {
  try {
    await setup();
    await showVersion();
  } catch (error) {
    core.setFailed(error.message);
  }
}

module.exports = run

if (require.main === module) {
  run();
}