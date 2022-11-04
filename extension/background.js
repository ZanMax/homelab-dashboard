const url = chrome.runtime.getURL('config.json');

function doSomething(json) {
    console.log(json);
}

fetch(url)
    .then((response) => response.json()) //assuming file contains json
    .then((json) => doSomething(json));

chrome.runtime.onMessage.addListener((message) => {
    console.log(message);
});