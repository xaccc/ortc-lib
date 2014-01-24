#import <UIKit/UIKit.h>
#include <ortc/internal/ortc_MediaManager.h>

@interface ViewController : UIViewController
{
    IBOutlet UIButton* _btnTest1;
    IBOutlet UIButton* _btnTest2;
    IBOutlet UIButton* _btnTest3;
    IBOutlet UIButton* _btnTest4;
    IBOutlet UIButton* _btnTest5;
    IBOutlet UIButton* _btnTest6;
    IBOutlet UIImageView* _imgView1;
    IBOutlet UIImageView* _imgView2;
    IBOutlet UIImageView* _imgView3;
  
    IBOutlet UITextField* receiverIPAddressTextField;
  
    ortc::IMediaManagerDelegatePtr mediaManagerDelegate;
    std::list<ortc::IMediaStreamPtr> sendMediaStreams;
    std::list<ortc::IMediaStreamPtr> receiveMediaStreams;
    std::list<int> audioChannels;
    std::list<int> videoChannels;
}

-(IBAction)test1;
-(IBAction)test2;
-(IBAction)test3;
-(IBAction)test4;
-(IBAction)test5;
-(IBAction)test6;

-(void)setSendMediaStream:(ortc::IMediaStreamPtr)stream;

@end
