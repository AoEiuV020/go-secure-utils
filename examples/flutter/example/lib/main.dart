import 'package:flutter/material.dart';

import 'pages/rsa_test_page.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: '证书管理系统',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.blue),
        useMaterial3: true,
      ),
      initialRoute: '/rsa_test',
      routes: {'/rsa_test': (context) => const RsaTestPage()},
    );
  }
}
