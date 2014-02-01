NotificationBox implements some of the notificationbox element functionality in Firefox and Mozilla-based browsers using the Addon SDK. For any question or feedback please email lduros--at--member.fsf.org

You can create a notification as follows:
```javascript
var self = require("self");
var notification = require("notification-box").NotificationBox({
  'value': 'important-message',
  'label': 'This is a very important message!',
  'priority': 'CRITICAL_BLOCK',
  'image': self.data.url("gnu-icon.png"),
  'buttons': [{'label': "Do something about it!",
              'onClick': function () { console.log("You clicked the important button!"); }}]
});
```

It implements the following options:

    - value: value used to identify the notification
    - label: label to appear on the notification
    - image: URL of image to appear on the notification. You can also
      load a local image from the data folder, like in the example
    - priority: notification priority. Use one of the following:
          - INFO_LOW
          - INFO_MEDIUM
          - INFO_HIGH
          - WARNING_LOW
          - WARNING_MEDIUM
          - WARNING_HIGH
          - CRITICAL_LOW
          - CRITICAL_MEDIUM
          - CRITICAL_HIGH
          - CRITICAL_BLOCK
    - buttons: array of buttons to appear on the notification.
      You can use the following options:
        - accessKey: the accesskey to appear on the button
        - onClick: the callback function to trigger when button is activated.
        - label: the text to display on the button


Here is an overview of what the example above with the critical notification looks like:
![The Critical notification](https://raw.github.com/lduros/notificationbox/master/doc/images/critical-notification.png)

When using 'INFO_LOW' for the priority instead, you would see:
![Info Low notification](https://raw.github.com/lduros/notificationbox/master/doc/images/info-low-priority.png)

For more information on notificationbox: https://developer.mozilla.org/en-US/docs/XUL/notificationbox
