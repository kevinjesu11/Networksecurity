const fileInput = document.getElementById("file");
const fileName = document.getElementById("file-name");
const csvForm = document.querySelector("#csv-panel form");
const loading = document.getElementById("loading");

if (fileInput) {
    fileInput.addEventListener("change", function () {
        if (this.files.length > 0) {
            fileName.textContent = "Selected: " + this.files[0].name;
        } else {
            fileName.textContent = "No file selected";
        }
    });
}

if (csvForm) {
    csvForm.addEventListener("submit", function () {
        loading.style.display = "block";
    });
}

const urlForm = document.querySelector("#url-panel form");
const urlLoading = document.getElementById("url-loading");

if (urlForm) {
    urlForm.addEventListener("submit", function () {
        urlLoading.style.display = "block";
    });
}

const tabButtons = document.querySelectorAll(".tab-btn");
const panels = document.querySelectorAll(".panel");

tabButtons.forEach(function (btn) {
    btn.addEventListener("click", function () {
        tabButtons.forEach(function (b) { b.classList.remove("active"); });
        panels.forEach(function (p) { p.classList.remove("active"); });

        btn.classList.add("active");
        document.getElementById(btn.dataset.tab).classList.add("active");
    });
});