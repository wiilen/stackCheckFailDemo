//
//  ViewController.m
//  demo
//
//  Created by ByteDance on 2023/6/30.
//

#import "ViewController.h"
#include <stdio.h>
#include <string.h>

void testStackCheckFailed() {
    char str1[5];
    int i = 0;
    while (i < 100) {
        str1[++i] = 'a';
    }
}

void testStrcpy() {
    char str1[20] = "C programming";
    char str2[5];
    
    // copying str1 to str2
    strcpy(str2, str1);
}

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view.
    testStackCheckFailed();
//    testStrcpy();
}

@end
