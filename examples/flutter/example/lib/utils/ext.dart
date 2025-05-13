import 'package:flutter/material.dart';

extension ContextExtension on BuildContext {
  Future dialog({
    String? title,
    required String content,
    List<Widget>? actions,
  }) async {
    if (!mounted) {
      return;
    }
    return await dialogWithWidget(
      title: title,
      content: Text(content),
      actions: actions,
    );
  }

  Future dialogWithWidget({
    String? title,
    required Widget content,
    List<Widget>? actions,
  }) async {
    if (!mounted) {
      return;
    }
    return await showDialog(
      context: this,
      builder:
          (context) => AlertDialog(
            title: title != null ? Text(title) : null,
            content: content,
            actions:
                actions ??
                [
                  TextButton(
                    onPressed: () => Navigator.pop(context),
                    child: Text(
                      '确定',
                      style: TextStyle(color: Theme.of(context).primaryColor),
                    ),
                  ),
                ],
          ),
    );
  }

  void showSnackBar({
    required String content,
    Duration duration = const Duration(seconds: 3),
  }) {
    ScaffoldMessenger.of(this).showSnackBar(
      SnackBar(
        content: Text(content),
        duration: duration,
        backgroundColor: Theme.of(this).primaryColor,
        behavior: SnackBarBehavior.floating,
      ),
    );
  }
}
