const vscode = require("vscode")
const axios = require("axios")

function activate(context) {
  console.log('Docker vulnerabilities extensions is active!')
  let disposable = vscode.commands.registerCommand(
    "extension.dockerVulnerabilities",
    async function() {
      vscode.window.showInformationMessage("Searching vulnerabilities")
      let editor = vscode.window.activeTextEditor
      let fileName = getFileName(editor)
      if (fileName === "Dockerfile") {
        let line = getLine(editor)
        if (line) {
          line = line.trim().toLowerCase().replace("from ", "")
          let image = line.split(":")[0]
          let tag = line.split(":")[1]
          let username = context.globalState.get('username')
          let password = context.globalState.get('password')
          if (!username) {
            username = await showPrompt('username', context)
            if (username) context.globalState.update("username", username)
          }
          if (!password) {
            password = await showPrompt('password')
            if (password) context.globalState.update("password", password)
          }
          let token = await getToken(username, password, context)
          if (token) {
            let vulnerabilities = await getVulnerabilities(image, tag, token)
            if (vulnerabilities) openSummary(vulnerabilities)
          }
        }
      }
    }
  )

  context.subscriptions.push(disposable)
}


const showPrompt = (label) => {
  let options = {
    prompt: `Dockerhub ${label}`,
    placeHolder: label,
    password: label === 'password'
}

  return vscode.window.showInputBox(options)
}

exports.activate = activate

async function getToken(username, password, context) {
  try {
    let response = await axios.post("https://hub.docker.com/v2/users/login/", {
      username,
      password
    })
    return response.data.token
  } catch (error) {
    context.globalState.update('username', '')
    context.globalState.update('password', '')
    vscode.window.showErrorMessage(`Error getting token from Docker Hub: ${error}`)
  }
}

async function getVulnerabilities(image, tag, token) {
  const endpoint = `https://hub.docker.com/api/nautilus/v1/repositories/result?namespace=library&reponame=${image}&tag=${tag}&detailed=1`;
  try {
    const response = await axios.get(endpoint, { headers: { authorization: `JWT ${token}` } })
    return response.data
  } catch (error) {
    vscode.window.showErrorMessage(`Error getting vulnerabilities: ${error}`)
  }
}

async function openSummary(vulnerabilities) {
  const doc = await vscode.workspace.openTextDocument({
    language: 'markdown',
    content: getTemplate(vulnerabilities)
  });
  vscode.window.showTextDocument(doc)
}

function getLine(editor) {
  let lines = editor.document.getText().split("\n")
  let line = lines.find(l => l.includes("FROM "))
  return line
}

function getFileName(editor) {
  let filePath = editor.document.fileName
  let splitted = filePath.split("/")
  let fileName = splitted[splitted.length - 1]
  return fileName
}

function getTemplate(imageInfo) {
  return `
# Docker vulnerabilities

* Critical: ${imageInfo.scan_details.num_critical}
* Major: ${imageInfo.scan_details.num_major}
* Minor: ${imageInfo.scan_details.num_minor}
* Healthy: ${imageInfo.scan_details.num_healthy}


## Vulnerabilities:

${getCVES(imageInfo.scan_details.blobs)}

`
}

function getCVES(blobs) {
  let cves = []
  for (let blob of blobs) {
    for (let component of blob.components) {
      if (component.vulnerabilities) {
        for (let vulnerability of component.vulnerabilities) {
          cves.push(`
          component: ${component.component},
          version: ${component.version},
          cve: ${vulnerability.cve},
          summary: ${vulnerability.summary}`)
        }
      }
    }
  }
  return cves.join('\n')
}

function deactivate() {}

module.exports = {
  activate,
  deactivate
}
