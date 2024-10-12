# Answer in my observation

## Task 4
- It can be seen that when adding `Samy` as a friend, we will send a HTTP request which has an URL is `http://www.seed-server.com/action/friends/add?friend=59&__elgg_ts=...&__elgg_token=...&__elgg_ts=...&__elgg_token=...&logged_in=true`.
- The URL has 3 values which are `friend`, `__elgg_ts` and `__elgg_token`. We can see that only the `friend` value will not change if we add `Samy` a friend request in different time which we can add it to our url.
- Therefore, to succesffuly add `Samy` a friend request, we will need to add `__elgg_ts` and `__elgg_token` values, I see that when sending the request, in the `Debugger` tab next to the `Network` tab in `Web Developer Tool`, I have the source code of the target server, and in the `elgg.js` file, I see the `elgg.security.token.__elgg_ts` and `elgg.security.token.__elgg_token` variable, so I can use these to get these values to complete the task.
- Finally, in the request header, there's a field `X-Requested-With: XMLHttpRequest`, we have to create an AJAX request and it will send to Samy user a friend request.
- We can not launch a successful attack if the Elgg application only provide the `Editor mode` for the `About Me` field.

## Task 5
- The `Line 1` is used to check if Samy visits her profile then the attack will not launch.

## Task 6
- In attacker machine, running this command before injecting JS code to Samy's profile.
```
    python3 -m http.server <arbitrary port>
```
