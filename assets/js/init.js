// Check if the cookie "localStorage" is set
if (document.cookie.split('=')[0] !== 'localStorage_checked') {
    if (navigator.storage && navigator.storage.persist) {
        navigator.storage.persist().then((persistent) => {
        if (!persistent) {
            swal({
                title: "Failed to persist storage.",
                text: "We failed to persist your local storage.\n\nStorage may be cleared by the UA under storage pressure.\nPlease becareful with your data.\nDon't hesitate to export your data to a safe place.",
                icon: "warning",
                buttons: true,
                dangerMode: true,
            })
        }
        });
    }
    // set the cookie "localStorage" to "false" for 1 day
    var now = new Date();
    var time = now.getTime();
    var expireTime = time + 1000*36000;
    now.setTime(expireTime);
    document.cookie = 'localStorage_checked=true;expires='+now.toUTCString()+';path=/;SameSite=Strict';
}