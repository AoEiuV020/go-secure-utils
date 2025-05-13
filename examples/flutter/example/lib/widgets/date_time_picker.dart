import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../utils/ext.dart';

class DateTimePickerWidget extends StatelessWidget {
  final String title;
  final DateTime? date;
  final Function(DateTime) onChanged;
  final DateTime firstDate;
  final DateTime lastDate;

  const DateTimePickerWidget({
    super.key,
    required this.title,
    required this.date,
    required this.onChanged,
    required this.firstDate,
    required this.lastDate,
  });

  @override
  Widget build(BuildContext context) {
    return Row(
      children: [
        Expanded(
          child: TextField(
            readOnly: true,
            decoration: InputDecoration(
              labelText: title,
              border: const OutlineInputBorder(),
            ),
            controller: TextEditingController(
              text: date != null ? '${date!.toLocal()}'.split('.')[0] : '',
            ),
            onTap: () async {
              final selectedDate = await showDatePicker(
                context: context,
                initialDate: date ?? DateTime.now(),
                firstDate: firstDate,
                lastDate: lastDate,
              );
              if (selectedDate != null && context.mounted) {
                final selectedTime = await showTimePicker(
                  context: context,
                  initialTime: TimeOfDay.fromDateTime(date ?? DateTime.now()),
                );
                if (selectedTime != null && context.mounted) {
                  onChanged(
                    DateTime(
                      selectedDate.year,
                      selectedDate.month,
                      selectedDate.day,
                      selectedTime.hour,
                      selectedTime.minute,
                    ),
                  );
                }
              }
            },
          ),
        ),
        IconButton(
          icon: const Icon(Icons.copy),
          tooltip: '复制',
          onPressed: () {
            if (date != null) {
              Clipboard.setData(
                ClipboardData(text: '${date!.toLocal()}'.split('.')[0]),
              );
              context.showSnackBar(content: '已复制');
            }
          },
        ),
        IconButton(
          icon: const Icon(Icons.access_time),
          tooltip: '设为当前时间',
          onPressed: () {
            final now = DateTime.now();
            onChanged(now);
          },
        ),
        IconButton(
          icon: const Icon(Icons.calendar_month),
          tooltip: '加一个月',
          onPressed: () {
            if (date != null) {
              final newDate = date!.add(Duration(days: 30));
              onChanged(newDate);
            }
          },
        ),
        IconButton(
          icon: const Icon(Icons.calendar_today),
          tooltip: '加一年',
          onPressed: () {
            if (date != null) {
              final newDate = date!.add(Duration(days: 365));
              onChanged(newDate);
            }
          },
        ),
      ],
    );
  }
}
