
const buttonSubmit = document.getElementById('button-submit');
const inputRequestToken = document.getElementById('input-request-token');
const inputRedirectUrl = document.getElementById('input-redirect-url');

const requestToken = location.searchParams.get('request-token');
const redirectUrl = location.searchParams.get('redirect-url');

let invalidRequest = false;
if (requestToken) {
    inputRequestToken.value = request
} else {
    invalidRequest = true;
}

if (redirectUrl) {
    inputRedirectUrl.value = redirectUrl
} else {
    invalidRequest = true;
}

function captchaCallback(captchaToken) {
    if (invalidRequest) {
        return;
    }
    buttonSubmit.disabled = false;
}