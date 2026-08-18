addToLibrary({
    enable_run_button: function () {
        var sys = document.getElementById('runSysButton');
        if (sys)
            sys.disabled = false;
        var run = document.getElementById('runButton');
        if (run)
            run.disabled = false;
        var stop = document.getElementById('stopButton');
        if (stop)
            stop.disabled = true;
    },

    disable_run_button: function () {
        var sys = document.getElementById('runSysButton');
        if (sys)
            sys.disabled = true;
        var run = document.getElementById('runButton');
        if (run)
            run.disabled = true;
    },

    report_run_completion: function () {
        var statusText = document.getElementById('statusText');
        var statusBadge = document.getElementById('statusBadge');
        if (statusText)
            statusText.textContent = 'Completed';
        if (statusBadge)
            statusBadge.classList.remove('running');
        if (typeof term != 'undefined' && term) {
            term.write('\x1b[32m> Completed\x1b[0m\r\n');
        }
    },
})