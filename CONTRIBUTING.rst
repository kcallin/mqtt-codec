Contributing Changes
=====================

.. Adapted from http://wiki.eclipse.org/Development_Resources/Contributing_via_Git#The_Commit_Record
.. https://git-scm.com/book/en/v2/Git-Tools-Signing-Your-Work

If you have an idea for an enhancement then you are welcome to fork the
github repository at https://github.com/kcallin/mqtt-codec, make your
changes, and then submit a pull request.

Minimally, your git commit record must have the following:

1. Your name and e-mail address captured in the "Author" field.
2. A single line summary in the message field followed by a more
   detailed description.
3. A "Signed-off-by" entry with matching credentials in the message
   footer.

If the commit fixes a bug then a link should be included in the message
footer.  The id (bug number) of the bug should also be included in the
message summary.

You can specify additional authors using one or more "Also-by" entries
in the message footer.

For example:

::

    commit 862e6ff22ad56c10df6de3385ffa4c7d02363d1d
    Author: Joe Somebody <somebody@someplace.net>
    Date:   Mon Jun 17 17:19:38 2013 -0700

        [2] MqttPublish.payload must be bytes

        The MqttPublish payload parameter is stored and returned by
        MqttPublish.payload without checking that it is bytes.  This
        change adds an assertion that the payload parameter is bytes.

        Bug: https://github.com/kcallin/mqtt-codec/issues/3
        Also-by: Some Otherperson <otherperson@someplace.net>
        Signed-off-by: Joe Somebody <somebody@someplace.net>

The "Signed-off-by" entry is required. By including this, you confirm
that you are in compliance with the
`Certificate of Origin <https://www.eclipse.org/legal/DCO.php>`_.

Note that the footer entries must occur at the bottom of the commit
message and must not include any blank lines.


Signing off on a Commit
------------------------

Git contains built-in support for signing off on a commit.

From command-line `git`, add -s to the command:

.. code-block:: none

   $ git commit -s --gpg-sign[=<keyid>] -m "[2] MqttPublish.payload must be bytes"
