import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'package:file_picker/file_picker.dart';

import '../utils/ext.dart';

class FileInputField extends StatelessWidget {
  final String labelText;
  final TextEditingController controller;
  final bool readOnly;

  const FileInputField({
    super.key,
    required this.labelText,
    required this.controller,
    this.readOnly = false,
  });

  Future<void> _pickFile(BuildContext context) async {
    final result = await FilePicker.platform.pickFiles();
    if (result == null) return;
    final files = result.xFiles;
    if (files.isEmpty) return;
    final file = files.first;
    final content = await file.readAsString();
    controller.text = content;
  }

  Future<void> _copyToClipboard(BuildContext context) async {
    if (controller.text.isEmpty) return;
    try {
      await Clipboard.setData(ClipboardData(text: controller.text));
      if (context.mounted) {
        context.showSnackBar(content: '已复制到剪贴板');
      }
    } catch (e) {
      if (context.mounted) {
        context.dialog(content: '复制失败: ${e.toString()}');
      }
    }
  }

  Future<void> _pasteFromClipboard(BuildContext context) async {
    try {
      final data = await Clipboard.getData('text/plain');
      if (data?.text?.isNotEmpty ?? false) {
        controller.text = data!.text!;
      }
      if (context.mounted) {
        context.showSnackBar(content: '已粘贴');
      }
    } catch (e) {
      if (context.mounted) {
        context.dialog(content: '粘贴失败: ${e.toString()}');
      }
    }
  }

  Future<void> _saveFile(BuildContext context) async {
    try {
      final result = await FilePicker.platform.saveFile(
        dialogTitle: '保存文件',
        fileName: '$labelText.dat',
        bytes: Uint8List.fromList(controller.text.codeUnits),
      );

      if (result == null || controller.text.isEmpty) return;

      if (context.mounted) {
        context.dialog(content: '文件已保存至：$result');
      }
    } catch (e) {
      if (context.mounted) {
        context.dialog(content: '保存失败：${e.toString()}');
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Row(
      children: [
        Expanded(
          child: TextField(
            controller: controller,
            readOnly: readOnly,
            decoration: InputDecoration(
              labelText: labelText,
              border: const OutlineInputBorder(),
            ),
          ),
        ),
        IconButton(
          icon: const Icon(Icons.upload_file),
          onPressed: () => _pickFile(context),
          tooltip: '读取文件',
        ),
        IconButton(
          icon: const Icon(Icons.copy),
          tooltip: '复制',
          onPressed: () => _copyToClipboard(context),
        ),
        IconButton(
          icon: const Icon(Icons.paste),
          tooltip: '粘贴',
          onPressed: () => _pasteFromClipboard(context),
        ),
        IconButton(
          icon: const Icon(Icons.save_alt),
          tooltip: '保存文件',
          onPressed: () => _saveFile(context),
        ),
      ],
    );
  }
}
