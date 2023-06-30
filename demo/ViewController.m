//
//  ViewController.m
//  demo
//
//  Created by ByteDance on 2023/6/30.
//

#import "ViewController.h"
#include <stdio.h>
#include <string.h>

void test() {
    char str1[5];
    int i = 0;
    while (i < 100) {
        str1[++i] = 'a';
    }
}

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view.
    test();
}

@end
